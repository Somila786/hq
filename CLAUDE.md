# CLAUDE.md — Catalyst 7 KPI

Context file for Claude Code (or any agent) picking up this repo. Read this first.

## What this is

A self-hosted weekly KPI tracker for Catalyst 7: freelancer hours/deliverables,
revenue, clients, and leads. Built for a three-founder studio (Thembalethu,
Somila, Lethu) in Pretoria. Runs on the studio's own Cloudflare account, not a
third-party SaaS.

## Stack

- **Runtime:** Cloudflare Worker, plain JavaScript (ES modules), zero framework,
  zero runtime dependencies. `wrangler` is the only devDependency.
- **Database:** Cloudflare D1 (managed SQLite). Already created and live:
  `catalyst7-kpi`, id `ba622992-c6dc-4a9b-a099-3b8a5fbe3a83`. Schema in
  `schema.sql` — 14 tables (see ARCHITECTURE.md for the full breakdown).
  Pending migrations live in `migrations/`.
- **Frontend:** server-rendered HTML strings in `src/views.js`. No React, no
  build step, no client bundle. Forms POST and the page reloads. This is
  deliberate (perf-first, zero dependency surface) — don't introduce a
  framework without a real reason.
- **Auth:** PBKDF2 password hashing + D1-backed sessions + CSRF tokens + rate
  limiting + optional TOTP 2FA with backup codes + optional Google sign-in, all
  hand-rolled on Workers' native Web Crypto API (no auth library, no OAuth
  library). See `src/auth.js` and "Auth & security" below.

## File map

```
src/index.js    — router, all HTTP handling, the scheduled() Cron handler
src/db.js       — data access layer, every query lives here, all parameterized
src/auth.js     — password hashing, sessions, CSRF, rate limiting, TOTP,
                  backup codes, Google OAuth helpers
migrations/     — incremental SQL for the already-live database
src/views.js    — every page's HTML, plus the shared CSS/layout
schema.sql      — reference copy of the live D1 schema
wrangler.toml   — Worker config, D1 binding, monthly Cron Trigger
tests/d1.mjs    — node:sqlite wrapper matching D1's prepare/bind/first/all/run
tests/run.mjs   — 54 end-to-end tests (`npm test`)
tests/devserver.mjs — local preview server (`npm run preview`), seeded demo data
README.md       — deploy steps, day-to-day usage, known limitations
ARCHITECTURE.md — full frontend/backend/database/privacy/security breakdown
```

There is **no** `.github/workflows/deploy.yml` — earlier notes claimed one
existed, but it has never been in this tree. Adding it is a small job once the
repo is on GitHub.

## Current state — READ THIS FIRST

**The design port is complete and the app runs.** The theme plumbing that was
outstanding at the previous handoff has landed:

- `src/auth.js` exports `themeCookie(theme)` alongside the other cookie helpers.
- `src/index.js` computes `theme` from the `c7_theme` cookie on every request,
  serves a public `GET /theme/toggle` route ahead of the auth gate, and threads
  `theme` into all 30 `views.*Page()` call sites (plus `csrfGuard`, which now
  takes it so the 403 page matches the rest of the site).
- The mobile nav and the collapsible add-forms were verified in a real browser
  at 1280 / 1000 / 900 / 875 / 375 / 320px. One bug was found and fixed in
  `views.js`: `.hamburger-toggle:checked ~ .mobile-menu` sat outside the
  `@media (max-width:859px)` block, so a menu left open while the viewport
  widened stayed open underneath the restored desktop nav. It's now scoped to
  the breakpoint, with a regression test.
- README.md and ARCHITECTURE.md describe the real brand system.

The test suite was **not** in the handoff zip and has been rebuilt from the
description in "Testing" below: `tests/d1.mjs` (the D1 adapter) and
`tests/run.mjs` (54 tests). It is a reconstruction, not the byte-identical
original — it covers the same documented ground (auth, rate limiting, CSRF,
roles, audit, 2FA, retention/erasure, CHECK constraints) plus the new theme
routes and the checkbox-hack markup contracts. 54/54 pass.

**A second pass then added Google sign-in, security headers and 2FA backup
codes** (see "Auth & security" below). That pass introduced migration
`migrations/001_google_auth_and_backup_codes.sql`, which has **not** been run
against the live D1 database yet — do that before deploying, or `/security` and
Google sign-in will error on the missing tables.

### What's actually left

1. **Run the migration** — `npx wrangler d1 execute catalyst7-kpi --remote
   --file=./migrations/001_google_auth_and_backup_codes.sql`.
2. **Deploy** — `npx wrangler login && npx wrangler deploy`. Still a human step;
   no tool here pushes Worker code live.
3. **Push to GitHub** — the repo is committed locally but has no remote yet.
   Note README.md still contains a live founder setup token; make the repo
   private or rotate that token first.
4. **Optionally configure Google sign-in** — needs an OAuth client created in
   Google Cloud Console (steps in README.md). Without it the feature stays
   dormant and password login is unaffected.
5. Optional, in rough priority order: keyboard accessibility for the two
   checkbox-hack toggles (see ARCHITECTURE.md §1 — currently mouse/touch only),
   a `.github/workflows/deploy.yml`, edit/delete UI, self-serve founder invites.

## Auth & security

Three ways in, all landing on the same session:

- **Password** — PBKDF2, 100k iterations, SHA-256. Unchanged.
- **Google sign-in** — optional, off unless `GOOGLE_CLIENT_ID` +
  `GOOGLE_CLIENT_SECRET` are set. Authorization-code flow with PKCE, a
  single-use server-side `state` row, and a `nonce`. **Allowlist-only:** Google
  establishes identity, the `users` table decides authorisation, and an unknown
  email is a failed login, never an auto-provisioned account. `google_sub` is
  bound on first use so a reassigned email address can't inherit an account.
- **2FA** — TOTP as before, plus ten single-use backup codes. Both federated
  and password logins are gated by it when it's on.

The Google ID token's signature is deliberately *not* re-verified locally: it
is fetched server-to-server from Google's token endpoint over TLS, which is the
case Google's own guidance says needs no local check. Claims (`iss`, `aud`,
`exp`, `nonce`, `email_verified`) are all validated. If a token ever starts
arriving from anywhere else — the browser, a webhook — that code must grow
full JWKS/RS256 verification first.

Backup codes are hashed with a single SHA-256 pass rather than PBKDF2. That's
intentional and explained at the call site: they're 50 bits of CSPRNG output,
not a human-chosen secret, so there's no dictionary to stretch against and
redemption would otherwise cost ~1s.

Responses carry a strict CSP (`default-src 'none'`), HSTS, `X-Frame-Options`,
`nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP and
`Cache-Control: no-store`. Two caveats worth knowing before you touch them:

- `Referrer-Policy` **must** stay `same-origin` (or
  `strict-origin-when-cross-origin`). `no-referrer` silently breaks
  `/theme/toggle`, which reads the Referer to return you to the right page.
  There's a test pinning this.
- `script-src` uses `'unsafe-hashes'` plus a digest for each of the two
  pre-existing inline handlers. Despite the name it is not a wildcard — only
  those two exact strings can run. A test recomputes the digests from the
  rendered HTML, so editing either handler fails the suite rather than silently
  breaking the page. Delete both handlers and this could become
  `script-src 'none'`.

The 10 source design files this port was extracted from
(`Dashboard.dc.html`, `Freelancers.dc.html`, etc. + `support.js`) are a
prototyping-tool export — not directly usable code, already fully mined for
tokens/structure into `views.js`. No need to go back to them unless a page
looks visually wrong and you want to diff against the original mockup.

Security hardening pass is complete: login rate limiting, CSRF protection,
audit log, optional TOTP 2FA, error log, monthly retention review with a
founder-approved erasure action. All of it is covered by an end-to-end test
suite (see Testing below) — 54/54 passing as of the last run.

## Testing

There's no test framework dependency — tests run against a real SQLite engine
(Node's built-in `node:sqlite`, experimental as of Node 20/22) standing in for
D1, exercising the actual `src/` code, not a reimplementation. If you add a
route or a query, extend this pattern rather than introducing Jest/Vitest
unless there's a real reason to.

The adapter (`tests/d1.mjs` — `D1Statement`/`makeEnv`) wraps `node:sqlite` to
match D1's `.prepare().bind().first()/.all()/.run()` API exactly, so tests are
high-fidelity. `makeEnv()` returns a fresh in-memory database with `schema.sql`
applied; each test gets its own, so there's no cross-test state.

Tests drive the real Worker through real `Request` objects
(`worker.fetch(req, env)`) — routing, cookies, CSRF and role checks all
execute for real. Assert on database state and response headers/status rather
than on markup, except for the two CSS-only interaction patterns, which have
no JS to fail loudly and so are guarded by explicit markup assertions.

```bash
npm test          # Node 23+
node --experimental-sqlite tests/run.mjs   # Node 20/22
npm run preview   # real app + demo data at localhost:8788, for eyeballing UI
```

## Known gaps — don't be surprised by these, they're intentional v1 scope cuts

- No edit/delete UI for clients/leads/freelancers/revenue rows — add + status
  toggle only. Corrections go via `wrangler d1 execute`.
- No self-serve founder invite UI — adding a founder is a manual D1 insert
  (documented in README.md).
- No CI/CD workflow in the repo at all (see the file map note above).
- The mobile nav and the collapsible add-forms are CSS-only and therefore not
  keyboard-operable. Deliberate trade-off for the zero-JS constraint, but it is
  a real accessibility gap — see ARCHITECTURE.md §1.
- The theme preference is per-browser (a cookie), not stored per user account.

## Brand system

Three colors only:
- Black `#0D0D0D`
- Cream `#F5EDD8`
- Red `#C1272D` (accent — needs a lightened tint `#E2726B` for small text in
  dark mode specifically; full red drops to ~3.3:1 contrast on `#0D0D0D` at
  small sizes, fine at ~5:1 on cream)

Dark mode: black bg, cream text. Light mode: cream bg, black text. Red is the
one accent in both. Don't introduce other colors without a reason — see
ARCHITECTURE.md's frontend section and the design brief referenced there for
the full rationale.

## Non-negotiables when extending this

- Every query stays parameterized (`.bind()`) — no string-concatenated SQL.
- Every mutating route stays behind the CSRF check (`csrfGuard`) and logs to
  `audit_log` via `db.logAudit()`.
- Role checks (`founder` vs `freelancer`) happen server-side in `index.js`,
  never just hidden in the UI.
- Retention/erasure logic never auto-deletes — it flags for a human decision.
  Keep it that way.
