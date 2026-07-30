# Catalyst 7 HQ — Full System Architecture & Requirements

The product is branded **Catalyst 7 HQ** in the interface. The Cloudflare Worker
and D1 database are still named `catalyst7-kpi` — infrastructure names are
awkward to change and nobody sees them, so they were deliberately left alone.

Status: frontend, backend, and database are built and live in your Cloudflare account.
Deploy (`wrangler deploy`) and domain binding are the only steps still on you.

---

## 1. Frontend

- **No framework, no build step.** Server-rendered HTML strings (`src/views.js`), generated per-request by the Worker. Forms POST directly to routes; the page reloads. No React, no bundler, no npm dependency shipped to the browser. Client-side JS totals well under a kilobyte across the whole site: one `onchange` auto-submit on the lead-stage dropdown, two `confirm()` guards on destructive actions, and one small delegated listener that makes the theme switch instant. Every one of them is progressive enhancement — with scripting blocked the site still works, just with a page reload where there would have been an instant change.
- **Why this choice:** zero dependency surface, zero build pipeline to maintain, loads fast on mobile data (matches C7's mobile-first / performance-as-accessibility standard — no JS bundle to download at all).
- **Pages:** login, 2FA verification, first-time password setup, security/2FA self-service, founder dashboard, freelancers, clients, leads, revenue, **team**, audit log, error log, retention review, freelancer weekly log, freelancer history.
- **Brand design system.** Three colours only — black `#0D0D0D`, cream `#F5EDD8`, red `#C1272D`. Dark mode is black-on-cream-text, light mode is the inverse; red is the single accent in both. Small red text in dark mode uses a lightened tint `#E2726B`, because full red only reaches ~3.3:1 on `#0D0D0D` at small sizes (it's fine at ~5:1 on cream). Everything is driven by CSS custom properties on `:root`, overridden by `html[data-theme="light"]`.
- **Theming is server-rendered, switched in-page.** The theme lives in a `c7_theme` cookie. `src/index.js` reads it on every request and passes `theme` into each `views.*Page()` call; `layout()` stamps it onto `<html data-theme="...">`, so the correct theme is in the very first byte of HTML and there is no flash on load. Switching is handled in-page by a ~480-byte delegated click listener (`THEME_SCRIPT` in `views.js`) that flips the attribute and writes the cookie itself — measured at well under a millisecond, with no navigation. The `<a href="/theme/toggle">` underneath is the no-JS fallback and still works on its own: the server flips the cookie and redirects back to the same-origin page you came from (a cross-origin or malformed Referer falls back to `/`). This cookie is deliberately **not** `HttpOnly` — it holds a display preference, not a secret, and a browser silently discards a `document.cookie` write over an HttpOnly cookie of the same name, which would make the theme revert on the next load.
- **Two pure-CSS interaction patterns, no JS.** The mobile nav and the collapsible "Add X" forms on Freelancers/Clients/Leads/Revenue are both built on the checkbox hack: a hidden `<input type="checkbox">` plus a `<label for="...">` and the `~` sibling combinator. Both depend on the checkbox being emitted *before* its siblings in the markup — there's a test asserting that ordering.
- **Responsive:** single embedded CSS block. Dashboard metrics use a `auto-fit` card grid; the nav collapses to a hamburger below 860px; tables sit in `overflow-x: auto` wrappers so they scroll within their panel instead of blowing out the page.
- **Verified:** the checkbox-hack nav and add-forms were checked in a real browser at 1280 / 1000 / 900 / 875 / 375 / 320px. Tables scroll inside their own wrapper down to 320px with no page-level horizontal overflow, so the old "not tested on narrow screens" gap is closed. Note that width media queries are evaluated against the viewport *including* the classic scrollbar, so on a desktop browser with a 15px scrollbar the nav switches to mobile at roughly 844px of usable width rather than 860px.
- **Known accessibility gap:** the checkbox-hack controls are labels wrapping a `display:none` checkbox, so neither the hamburger nor the "Add X" buttons are reachable by keyboard or announced as buttons by a screen reader. Everything else on the page (all real links, inputs and submit buttons) is fully keyboard-navigable, and no data entry or destructive action is behind these toggles — but a founder or freelancer navigating by keyboard alone cannot open the mobile nav or the add-forms. Fixing it properly means either a focusable checkbox styled as the control, or a small amount of JS. Worth revisiting if anyone actually needs it. The hamburger's 34×34px hit area is also under the 44×44 touch-target guideline.

## 2. Backend

- **Runtime:** Cloudflare Worker, plain JavaScript (ES modules), no framework (no Hono/Express) — one `fetch(request, env)` handler routing on pathname + method.
- **Files:** `src/index.js` (routing), `src/db.js` (data access, parameterized queries only), `src/auth.js` (password hashing, sessions, week math).
- **Auth mechanism:** PBKDF2 (Web Crypto, 100,000 iterations, SHA-256) for password hashing — no plaintext password ever touches the database or me. Sessions are random 32-byte tokens stored in a `sessions` table, set as `HttpOnly; Secure; SameSite=Lax` cookies, 30-day expiry. Optional Google sign-in and optional TOTP 2FA (with backup codes) sit alongside, all landing on the same session — see section 6.
- **Roles enforced server-side:** `founder` (full access) vs `freelancer` (own weekly-log row only) — checked on every route, not just hidden in the UI.
- **Account management (`/team`, founders only):** create founder or freelancer logins, re-issue a one-time invite link, or revoke access. The role is validated against a fixed list server-side, never taken from the form as submitted, so a freelancer cannot mint a founder even by forging a request. A freelancer login must be linked to an existing freelancer profile at creation, because `/log` resolves rows through `freelancer_id` and an unlinked account would sign in to an error. Revoking clears credentials, 2FA and any Google link, and deletes live sessions immediately — being signed out everywhere is the point. Two lockout guards: you cannot revoke yourself, and you cannot revoke the last founder who actually has a working login. Every action is audited.
- **Zero third-party runtime dependencies** — only `wrangler` itself as a devDependency. Nothing to audit for supply-chain risk.

## 3. Database

Cloudflare D1 (managed SQLite), already created and live: `catalyst7-kpi` (`ba622992-c6dc-4a9b-a099-3b8a5fbe3a83`).

| Table | Purpose | Personal information held |
|---|---|---|
| `users` | Login accounts + role | Email, name, password hash + salt |
| `freelancers` | Contractor roster | Name, email, rate |
| `clients` | Client roster | Name, contact name/email |
| `leads` | Pipeline | Name, company, contact email |
| `weekly_entries` | Freelancer hours/deliverables per week | Linked to freelancer_id |
| `revenue_entries` | Revenue per week per client | Amount, client link |
| `sessions` | Login sessions | Session token + CSRF token only (not personal data) |
| `pending_logins` | In-progress 2FA logins (5 min TTL) | User link only |
| `login_attempts` | Rate-limiting record | Email + IP, no password |
| `audit_log` | Who-did-what history | User name/id per action |
| `error_log` | Unhandled app errors | Request path + error message |
| `retention_flags` | Records due for a retention decision | Entity link + reason |
| `oauth_states` | In-flight Google sign-in handshakes (10 min TTL, single-use) | None — nonce + PKCE verifier only |
| `totp_backup_codes` | Single-use 2FA recovery codes | None — SHA-256 hashes only |

14 tables total now (7 original + 5 in the security hardening pass + 2 for Google sign-in and backup codes).

`users` also gained a `google_sub` column, holding Google's stable subject id once an account has been linked.

Migration `001` (the two newest tables plus `users.google_sub`) **has been applied to the live database** — verified against a rebuild of the previous schema, producing a structurally identical result. `migrations/001_...sql` is kept for rebuilding from scratch.

- All queries are parameterized (`.bind()`) — no string-concatenated SQL, so no SQL injection surface.
- `CHECK` constraints enforce valid values at the database layer (e.g. lead stage, revenue type) — tested live, confirmed rejecting bad data.
- No ORM. Deliberate — this schema is small enough that a query layer adds more indirection than value.
- All of the above verified with 63 end-to-end tests (`tests/run.mjs`) run against a real SQLite engine (Node's `node:sqlite`) loaded with this exact schema and exercising the actual `src/` code — not a reimplementation. All 63 pass.

## 4. Privacy — POPIA

This system is a **Responsible Party** under POPIA for the data it holds (it's C7's own contractor/client/lead records, not data processed on someone else's behalf, so the "Operator" clauses don't apply here — those matter for *client* systems, not this one).

| Data | Purpose | Lawful basis | Condition met? |
|---|---|---|---|
| Freelancer name/email/rate | Engagement + payment management | Contract | Yes |
| Client contact info | Commercial relationship management | Contract / legitimate interest | Yes |
| Lead name/company/email | Sales pipeline | Legitimate interest | Partial — no opt-out/removal path yet |
| Login credentials | Access control | Contract (necessary for service) | Yes — hashed, never stored plaintext |

- **No sensitive personal information collected** — no ID numbers, no banking details, no health data. Good data-minimisation posture by default.
- **Information Officer:** should be the same person as C7's existing IO (Thembalethu, per your regulatory framework) — this system doesn't need a separate one, but it should be brought under the same POPIA governance rather than treated as exempt because it's "just internal."
- **Data subject rights (erasure): now built.** `/retention` gives founders a working right-to-erasure action — clears name/email/contact fields on a lead or freelancer while keeping linked financial rows (past revenue/hours) intact for accurate historical reporting. Access/correction requests are still a manual D1 query, but deletion is no longer just a manual process.
- **Retention: now built.** A monthly Cron Trigger (1st, 03:00 UTC) flags `lost` leads and inactive freelancers with 365+ days of no activity into a review queue at `/retention`. It flags, never auto-deletes — a founder makes the keep/erase call on each one.
- **Audit trail: now built.** Every mutation (freelancer/client/lead/revenue changes, 2FA changes, retention decisions) is logged with who/what/when at `/audit` — this is also your breach-investigation trail if something looks wrong.
- **Breach protocol:** still no automated alerting if the app is queried or accessed unusually — see Security below. The audit log gives you the forensic trail *after* you know to look; it doesn't yet proactively tell you *when* to look.

## 5. Hosting & Infrastructure

- **Account:** your existing Cloudflare account — same one already running `catalyst7-businesscard`. No new hosting relationship, no new bill by default.
- **Domain:** the zone is already on that account, so binding `kpi.catalyst7.[yourdomain]` to the Worker is a dashboard click (Workers & Pages → catalyst7-kpi → Domains & Routes → Add Custom Domain) — Cloudflare issues the certificate and DNS record automatically.
- **Cost at this scale:** effectively R0/month. Workers free tier is 100,000 requests/day; D1 free tier is 5GB storage with generous read/write limits. Three founders and a handful of freelancers checking a weekly dashboard won't come close to either ceiling.

## 6. Security

**In place (original build):**
- TLS/HTTPS automatic via Cloudflare on any custom domain.
- Passwords hashed (PBKDF2, 100k iterations), never stored or logged in plaintext.
- Parameterized SQL throughout — no injection surface.
- `HttpOnly / Secure / SameSite=Lax` session cookies.
- Role checks enforced server-side on every route.

**Closed in this pass — the gap list from the first version, now addressed:**
- **Login rate limiting** — 5 failed attempts per account or 20 per network IP locks logins for 15 minutes (D1-backed, no extra bindings). Same limiter covers the 2FA code step. Tested: 6th consecutive wrong password returns 429.
- **CSRF protection** — every session gets its own token, embedded in every form, verified server-side on every POST. Tested: a POST missing the token is rejected with 403.
- **Audit log** — who did what, when, on every create/update action. `/audit`, founders only.
- **2FA (TOTP)** — optional, self-service at `/security`. Standards-correct RFC 6238 implementation (no external library — built on Workers' native Web Crypto, cross-validated against an independent Python implementation). Login flow correctly routes through a `/login/2fa` step when enabled.
- **Error log** — unhandled exceptions now land in `error_log` with path + message, viewable at `/errors` (founders only), in addition to Cloudflare's own free Workers Analytics.
- **Retention review** — monthly Cron Trigger flags stale records; founders resolve each one as Keep or Erase at `/retention`.

**Closed in the Google-auth / hardening pass:**
- **Google sign-in (optional)** — OAuth 2.0 authorization-code flow with PKCE, a single-use server-side `state` row and a `nonce`, all hand-rolled on Web Crypto and `fetch` (no OAuth library, still zero runtime dependencies). **Authentication is federated; authorisation is not.** A valid Google identity for an email that isn't already in `users` is a *failed login* — nothing is auto-provisioned. Google's `sub` is bound on first sign-in, so a Workspace address later reassigned to a different person is refused and audited. 2FA is not bypassed by it. Off entirely unless `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` are configured.
  - *Design note:* the ID token's signature is not re-verified locally, because it's fetched server-to-server from Google's token endpoint over TLS — the case Google's own guidance exempts. All claims (`iss`, `aud`, `exp`, `nonce`, `email_verified`) are checked. This is only sound while the token never arrives from an untrusted path; the code comment says so, and any move to a browser-delivered token needs full JWKS/RS256 verification first.
- **2FA backup codes** — ten single-use recovery codes issued when 2FA is enabled, shown once, stored as SHA-256 hashes (deliberately not PBKDF2: they're 50 bits of CSPRNG output, not a human-chosen secret). Redeemable at the code prompt in place of TOTP, regenerable from `/security`, and cleared when 2FA is switched off. Redemption is audited with the remaining count.
- **Security response headers** — strict CSP (`default-src 'none'`, no external origin permitted at all, `script-src` limited to digests of the two pre-existing inline handlers), HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, `Permissions-Policy`, COOP/CORP, and `Cache-Control: no-store` so authenticated pages don't survive logout in the browser cache. Verified in a real browser: both inline handlers still compile, `fetch()` is blocked by `connect-src`, and no violations are reported.
- **Malformed POST bodies** no longer surface as 500s that write to `error_log` — an unparseable body is treated as an empty form and falls through to the CSRF guard as a clean 403.

**Still open — genuinely lower priority, not built this pass:**
- **No brute-force protection on the CSRF/session layer beyond rate limiting** — e.g. no anomaly detection on session reuse from a new IP/device. Reasonable to defer at this scale.
- **No automated *alerting*** — the error log and audit log are places you can *look*, but nothing pushes a notification when something's wrong. Cloudflare Notifications (dashboard, free) can alert on error-rate spikes; nothing here does that yet.

## 7. Deployment & Operations

- **CI/CD: not present in this repo.** Earlier drafts of this document described a `.github/workflows/deploy.yml` ready to auto-deploy on push to `main` via `cloudflare/wrangler-action`; that file is **not** in the current tree. Whenever it is added it will still need two things: the repo actually on GitHub, and a `CLOUDFLARE_API_TOKEN` repo secret. Until then, `npx wrangler deploy` from a terminal is the deploy path. `npm test` is the pre-deploy gate to run by hand.
- **Backups:** D1 has point-in-time recovery built into the Cloudflare platform (up to 30 days) with no extra configuration — worth confirming this is enabled on your account tier, but nothing for us to build.
- **No staging environment** — one production database, no preview/test copy. Fine for now given the low change frequency; worth revisiting if you start iterating on the schema often.
- **Test coverage:** 63 end-to-end tests (`npm test`) exercise the actual shipped code (not a reimplementation) against a real SQLite engine standing in for D1 — login, rate limiting, CSRF enforcement, 2FA enable + login flow, retention scan + erasure, audit logging, role-based access, theme cookie plumbing, and the checkbox-hack markup contracts all covered. All 63 pass. Not wired into CI yet (see above) — currently a manual `node` script, not something that runs automatically on every change.
- **Local preview:** `npm run preview` (`tests/devserver.mjs`) runs the real Worker against a seeded in-memory database on `http://localhost:8788`, pre-authenticated as a demo founder. It exists so a design change can be eyeballed at any viewport in seconds, offline, without Cloudflare credentials. `wrangler dev` remains the higher-fidelity check against the real D1 binding.

## 8. What's still needed — punch list, in priority order

1. **Apply the migration, then deploy** — `npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/001_google_auth_and_backup_codes.sql`, then `npm install && npx wrangler login && npx wrangler deploy` (on you — no tool available to me pushes Worker code live). The migration must land first: `/security` and Google sign-in both read tables it creates.
2. **Bind the custom domain** and activate your founder login via the `/setup/<token>` link.
3. **Turn on 2FA** for your founder account from `/security` once you're in — the mechanism is built, it's just off by default.
4. **Add the other two founders** (manual D1 insert for now — documented in the README).
5. **Decide who owns the retention review** — check `/retention` periodically (it'll be empty until records go stale for 365+ days, so this is a "set a calendar reminder for a few months out" item, not urgent).
6. Genuinely optional from here: wire up a GitHub Actions workflow if a repo gets created, add Cloudflare Notification alerts, build edit/delete UI for records, and give the CSS-only toggles keyboard support.

---

*Sections 1–3 and the database itself already exist in your Cloudflare account. Section 6's "closed in this pass" items are live in the code and covered by the test suite — they land the moment you deploy, no separate setup required except turning 2FA on, which is opt-in by design.*
