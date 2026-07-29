# Catalyst 7 KPI — Weekly Freelancer, Revenue, Client & Lead Tracker

Self-hosted on your own Cloudflare account. Cloudflare Worker (app + API) + D1 (SQLite-compatible database, already live).

## What's already done for you

- **Database created and live**: `catalyst7-kpi` (id `ba622992-c6dc-4a9b-a099-3b8a5fbe3a83`) in your Cloudflare account, schema applied (12 tables).
- **Your founder account is seeded**: `catalyst948@gmail.com`, role `founder`, waiting on a password.
- **All application code is written and integration-tested** — auth, dashboard, freelancer/client/lead/revenue management, freelancer weekly log-in flow, plus the full security layer below.
- **Security hardening pass complete**: login rate limiting, CSRF protection, an audit log, optional TOTP 2FA, an in-app error log, and a monthly data-retention review — see "Security & compliance features" below. 36 end-to-end tests cover all of it against a real SQLite engine standing in for D1; all 36 pass.
- **Brand design system applied**: the real Catalyst 7 palette (black / cream / red) with a working dark ↔ light toggle, a mobile nav, and collapsible add-forms — all server-rendered, still no client JS bundle. See "Look & feel" below.

## What I could NOT do for you

My tools can create and query D1 databases, but there is no tool available to me that pushes Worker *code* live — only `wrangler` (Cloudflare's own CLI, running from your machine, authenticated as you) can do that. So the very last step is on you, and it's one command.

## Deploy (3 steps, ~5 minutes)

1. Open a terminal in this `catalyst7-kpi/` folder.
2. Install and deploy:
   ```bash
   npm install
   npx wrangler login      # opens a browser, log into the Catalyst 7 Cloudflare account
   npx wrangler deploy
   ```
3. Wrangler will print a URL like `https://catalyst7-kpi.<your-subdomain>.workers.dev`. Open it — you'll land on `/login`.

## Activate your founder account

Visit this one-time link (works on either the workers.dev URL or your custom domain once bound):

```
/setup/<setup-token-redacted-see-README>
```

e.g. `https://catalyst7-kpi.<your-subdomain>.workers.dev/setup/<setup-token-redacted-see-README>`

Set your password there. You're in. From the Dashboard nav you can then add the other two founders' logins yourself by inserting a row directly via `wrangler d1 execute` (see "Adding more founders" below) — there's no self-serve founder invite UI in v1, only freelancer invites.

## Point it at kpi.catalyst7.[yourdomain]

Your domain is already on Cloudflare (same account as this Worker), so:

1. Cloudflare dashboard → **Workers & Pages** → `catalyst7-kpi` → **Settings** → **Domains & Routes** → **Add** → **Custom Domain**.
2. Enter `kpi.catalyst7.yourdomain.tld` (whatever your real domain is) and confirm. Cloudflare creates the DNS record and issues the certificate automatically — no manual DNS editing needed since the zone is already on your account.
3. Give it a minute to propagate, then the app is live at that subdomain.

## Day-to-day use

- **Founders** (`/dashboard`, `/freelancers`, `/clients`, `/leads`, `/revenue`): log revenue and lead/client changes as they happen; check the dashboard weekly for the freelancer-hours vs last week, revenue vs last week, pipeline value, and who hasn't logged their week yet.
- **Freelancers** (`/log`): after you generate their invite link from the Freelancers page and send it to them, they set their own password and log hours/deliverables/status each week from `/log`. They only ever see and edit their own row.
- **Weeks** run Monday–Sunday (UTC). Revenue entries are tagged to a "week starting" date you pick when logging them, so you can backfill if needed.

## Look & feel

- **Three colours, two modes.** Black `#0D0D0D`, cream `#F5EDD8`, red `#C1272D`. Dark mode is cream-on-black, light mode is black-on-cream, red is the accent in both.
- **Switching themes:** the "Dark"/"Light" button in the top-right corner of every page (including the login page). Your choice is remembered for a year in a cookie and applied server-side, so there's no flicker on load and nothing to download. It's per-browser, not per-account — switching on your laptop doesn't change it on your phone.
- **On a phone:** the nav collapses into a ☰ menu below ~860px wide, and the "Add freelancer / client / lead / entry" forms stay collapsed until you tap the button, so the list you came to read is what you see first. Wide tables (Audit, Revenue) scroll sideways inside their own panel rather than stretching the page.
- **Still zero client-side JavaScript bundle** — the theme toggle, the mobile menu and the collapsible forms are all pure CSS and plain links. One caveat: because those toggles are CSS-only, the ☰ menu and the "Add X" buttons can't currently be operated by keyboard alone (see ARCHITECTURE.md, section 1).

## Testing & local preview

```bash
npm test        # 36 end-to-end tests against a real SQLite engine, no framework needed
npm run preview # real app + seeded demo data at http://localhost:8788, no Cloudflare login
```

`npm test` runs the actual Worker code against `node:sqlite` standing in for D1 — worth running before any deploy. On Node 20 or 22 you'll need `node --experimental-sqlite tests/run.mjs`; on Node 23+ it works as-is.

`npm run preview` is for eyeballing design changes offline; it signs you in automatically as a demo founder and uses a throwaway in-memory database, so nothing you click there touches real data. Use `npx wrangler dev` when you want the real D1 binding.

## Security & compliance features

- **Login rate limiting** — 5 failed attempts on one account, or 20 failed attempts from one network, locks logins for 15 minutes. Same limiter also protects the 2FA code step.
- **CSRF protection** — every form on every page carries a token bound to your session; the server rejects any POST where it doesn't match. Tested: a POST without the token gets a 403, not a silent failure.
- **Audit log** (`/audit`, founders only) — every create/update action records who did it, when, and what changed: freelancers added/invited/toggled, clients/leads/revenue created, lead stage changes, 2FA enabled/disabled, retention decisions.
- **Optional 2FA** (`/security`, any account) — standard TOTP, works with Google Authenticator, Authy, 1Password, etc. No external library — implemented directly against Workers' Web Crypto API and cross-checked against an independent Python HMAC-SHA1 implementation to confirm it's RFC 6238-correct. Recommended for founder accounts.
- **Error log** (`/errors`, founders only) — unhandled application errors land here with path and message. Cloudflare's own Workers Analytics (dashboard → catalyst7-kpi → Metrics) covers request volume/latency/uptime on top of this for free, zero setup.
- **Retention review** (`/retention`, founders only) — a Cron Trigger runs monthly (1st, 03:00 UTC) and flags lost leads and inactive freelancers with 365+ days of no activity. It never deletes anything itself — a founder reviews each flag and chooses "Keep" or "Erase personal info" (name/email/contact cleared, financial history like past revenue/hours stays intact for accurate historical reporting).

## Known v1 limitations (easy to extend later, intentionally left out to ship fast)

- No edit/delete UI for clients/leads/freelancers/revenue rows yet — only add + status toggle. Corrections go via `wrangler d1 execute catalyst7-kpi --remote --command "..."`.
- No self-serve founder invite UI — adding Somila and Lethu's logins is a manual D1 insert (see "Adding more founders" below).
- No email sending — invite links are generated in-app for you to paste into WhatsApp/email yourself, so no email connector dependency.
- No CI/CD — there's no `.github/workflows/` in this repo despite earlier notes saying otherwise. Once this is a GitHub repo, a deploy workflow using `cloudflare/wrangler-action` plus a `CLOUDFLARE_API_TOKEN` secret is a short file to add. Until then, deploy manually with `wrangler deploy` and run `npm test` first.
- 2FA has no backup/recovery codes — if a founder loses their authenticator, another founder needs to disable it for them via a direct D1 update (`UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE email = '...'`).

## Adding more founders (manual, until self-serve UI exists)

```bash
npx wrangler d1 execute catalyst7-kpi --remote --command \
  "INSERT INTO users (email, name, role, setup_token) VALUES ('somila@catalyst7.co', 'Somila', 'founder', lower(hex(randomblob(24))));"
```

Then run:
```bash
npx wrangler d1 execute catalyst7-kpi --remote --command \
  "SELECT setup_token FROM users WHERE email = 'somila@catalyst7.co';"
```

and send them `/setup/<that token>`.
