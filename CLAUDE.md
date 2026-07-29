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
  `schema.sql` — 12 tables (see ARCHITECTURE.md for the full breakdown).
- **Frontend:** server-rendered HTML strings in `src/views.js`. No React, no
  build step, no client bundle. Forms POST and the page reloads. This is
  deliberate (perf-first, zero dependency surface) — don't introduce a
  framework without a real reason.
- **Auth:** PBKDF2 password hashing + D1-backed sessions + CSRF tokens + rate
  limiting + optional TOTP 2FA, all hand-rolled on Workers' native Web Crypto
  API (no auth library). See `src/auth.js`.

## File map

```
src/index.js    — router, all HTTP handling, the scheduled() Cron handler
src/db.js       — data access layer, every query lives here, all parameterized
src/auth.js     — password hashing, sessions, CSRF, rate limiting, TOTP
src/views.js    — every page's HTML, plus the shared CSS/layout
schema.sql      — reference copy of the live D1 schema
wrangler.toml   — Worker config, D1 binding, monthly Cron Trigger
tests/d1.mjs    — node:sqlite wrapper matching D1's prepare/bind/first/all/run
tests/run.mjs   — 36 end-to-end tests (`npm test`)
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
`tests/run.mjs` (36 tests). It is a reconstruction, not the byte-identical
original — it covers the same documented ground (auth, rate limiting, CSRF,
roles, audit, 2FA, retention/erasure, CHECK constraints) plus the new theme
routes and the checkbox-hack markup contracts. 36/36 pass.

### What's actually left

1. **Deploy** — `npx wrangler login && npx wrangler deploy`. Still a human step;
   no tool here pushes Worker code live.
2. **Push to GitHub** — the repo is committed locally but has no remote yet.
3. Optional, in rough priority order: keyboard accessibility for the two
   checkbox-hack toggles (see ARCHITECTURE.md §1 — currently mouse/touch only),
   2FA backup codes, a `.github/workflows/deploy.yml`, edit/delete UI,
   self-serve founder invites.

The 10 source design files this port was extracted from
(`Dashboard.dc.html`, `Freelancers.dc.html`, etc. + `support.js`) are a
prototyping-tool export — not directly usable code, already fully mined for
tokens/structure into `views.js`. No need to go back to them unless a page
looks visually wrong and you want to diff against the original mockup.

Security hardening pass is complete: login rate limiting, CSRF protection,
audit log, optional TOTP 2FA, error log, monthly retention review with a
founder-approved erasure action. All of it is covered by an end-to-end test
suite (see Testing below) — 36/36 passing as of the last run.

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
- No 2FA backup/recovery codes.
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
