# ADR 001 — Audit against the C7 Web App Standard

**Status:** Accepted
**Date:** 2026-07-29
**Applies to:** Catalyst 7 HQ (`hq.catalyst7.co.za`)

## Context

Catalyst 7 HQ was built before the C7 Web Application Engineering, Security &
Resilience Standard was applied to it. This record captures the audit, what was
remediated, and — more importantly — which requirements were **deliberately not
followed**, so those decisions are visible rather than looking like oversights.

The app is an architectural outlier for the standard. The standard assumes a
React/SPA stack with client-side data fetching (Zustand, TanStack Query, error
boundaries). This is a Cloudflare Worker rendering HTML strings, with under a
kilobyte of client script and no build step. Several rules translate directly,
some are genuinely inapplicable, and a few exposed real defects.

## Stack declaration (standard §1)

| | |
|---|---|
| Deliverable | Stateful internal portal, **single-tenant** |
| Framework | None — hand-rolled Cloudflare Worker, ES modules |
| Language | JavaScript |
| State management | None client-side; server-rendered per request |
| Database | Cloudflare D1 (SQLite), raw parameterized SQL, no ORM |
| Infrastructure | Cloudflare Workers + D1 + Cron Triggers |
| Validation | Hand-rolled guards — no Zod/Pydantic |

## Remediated

1. **Credential hygiene (§5, query projections).** `getSessionUser()` used
   `SELECT u.*`, loading `password_hash`, `password_salt` and `totp_secret` into
   memory on *every authenticated request*. Now an explicit projection.
   `getUserById` / `getUserByEmail` are credential-free and expose a
   `has_password` flag instead. Exactly one function — `getUserCredentials()` —
   returns password material, so a careless `user.password_hash` elsewhere reads
   `undefined` rather than a live hash.

2. **Idempotency (§4A).** Every form now carries a single-use `_nonce` beside
   the session `_csrf`. Create routes claim it via `INSERT OR IGNORE`; a repeat
   finds it taken and redirects without re-running the handler. This closes a
   real defect — a double-clicked "Add entry" previously created two revenue
   rows, corrupting the figures the dashboard exists to report. Post/Redirect/Get
   already handled refresh; this handles the double-click race.

3. **Audit fields (§4D).** `audit_log` gained `ip_address` and `status`. Who/what/
   when alone doesn't support an incident investigation without *from where* and
   *did it work* (POPIA §17). Surfaced on `/audit`.

4. **Unauthorized state (§2).** Authenticated users hitting a route outside
   their role now get an explicit restricted-access page instead of a bare
   "Not found."

5. **Empty-state CTAs (§2).** Empty tables now offer a creation action.

6. **Supply chain & secrets (§3C).** Added CI running the suite against both the
   source and the single-file build, `npm audit --audit-level=high`, and a
   gitleaks job. Added a dependency-free `.githooks/pre-commit` that blocks
   committed secrets and gates on tests — verified to block a leaked setup token
   and a private key while allowing ordinary commits.

## Deliberate deviations

**`SameSite=Lax`, not `Strict` (§3A).** Strict means anyone following a link into
HQ from WhatsApp or email arrives logged out. For a tool reached primarily via
invite links, that is a material usability cost. Lax still blocks cross-site
POST — the CSRF vector — and per-session CSRF tokens cover it regardless.

**404, not an Unauthorized status (§2).** The standard asks for an explicit
restricted-access state; we render one, but the HTTP status stays 404. A 403
confirms the resource exists, which tells an unauthorised account more than it
should learn. The page explains; the status code stays quiet.

**`SELECT *` retained on business tables.** Removed everywhere it touched
`users`, where it was a genuine secret-hygiene problem. Left on `clients`,
`leads`, `freelancers` and `weekly_entries`: the rows are small, D1 is co-located
with the Worker, so the stated rationale (wire payload) is negligible, and
enumerating columns in a schema still in flux invites "column exists but the view
renders undefined" bugs. Revisit if these tables grow wide or gain sensitive
columns.

**No tenant isolation (§3A).** Single-tenant by design — there is no `tenant_id`
anywhere. **This becomes a real gap the moment a second studio is hosted**, and
retrofitting row-level isolation onto an app with live data is expensive. If
multi-tenancy is ever on the table, do it before there is more data, not after.

**No Idempotency-Key header (§4A).** There is no JSON API — every mutation is an
HTML form post. The form nonce is the same guarantee in the idiom that actually
applies here.

## Not applicable

File-upload inspection (no uploads), CORS (no cross-origin API), background job
queues (no long-running work; the one batch job is a Cron Trigger), global SDK
client reuse (the D1 binding is supplied per-request by the runtime), secrets
caching (env vars are already in memory).

## Still open

- **Circuit breaker (§4B)** on the Google token endpoint. It has try/catch and
  degrades to a friendly error rather than a 500, but no breaker or backoff. Low
  priority: one downstream, used only during sign-in.
- **General API rate limiting (§3B).** Auth is limited to the standard's 5/15min.
  There is no 100 req/min ceiling on ordinary page loads. Cloudflare rate-limiting
  rules at the zone would be the cheaper place to add this than in application code.
- **PII/log scrubbing (§3C).** `error_log` stores raw stack traces. Low risk given
  they originate from our own code, but there is no redaction layer.
- **Tamper-evident audit log (§4D).** `audit_log` is an ordinary table. Anyone with
  D1 access can edit it. Genuine hash-chaining would be needed to call it
  tamper-*evident*; today it is tamper-*visible* only to someone already watching.
- **CI is inert** until the repository is on GitHub.

## Consequences

The four defects that could actually cause harm — credentials in memory on every
request, duplicate financial records from a double-click, an audit trail too thin
to investigate with, and no barrier to committing a secret — are closed and
covered by tests. The deviations above are choices, and this document is where
they are defended. Anyone reading the code who thinks "that's wrong" should find
their objection answered here, or discover we were wrong.
