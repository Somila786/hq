// Server-rendered HTML views. Plain template strings -- no build step, no framework.
// Design system ported from the Catalyst 7 brand design pass (see ARCHITECTURE.md).
// Theme (dark/light) is server-driven via a cookie set at /theme/toggle -- no
// client JS needed for it. Mobile nav uses a CSS-only checkbox pattern.
// The only client JS anywhere on the site: one onchange auto-submit on the
// lead-stage dropdown, and one confirm() on the retention "Erase" action --
// both pre-existing, neither introduced by this design pass.

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function csrfField(csrf) {
  return `<input type="hidden" name="_csrf" value="${esc(csrf)}" />`;
}

function money(n) {
  const v = Number(n || 0);
  return "R" + v.toLocaleString("en-ZA", { maximumFractionDigits: 0 });
}

function delta(curr, prev) {
  const c = Number(curr || 0), p = Number(prev || 0);
  if (p === 0 && c === 0) return { text: "no change", cls: "flat" };
  if (p === 0) return { text: "new", cls: "up" };
  const pct = Math.round(((c - p) / p) * 100);
  if (pct > 0) return { text: `+${pct}% vs last wk`, cls: "up" };
  if (pct < 0) return { text: `${pct}% vs last wk`, cls: "down" };
  return { text: "flat vs last wk", cls: "flat" };
}

// pill kind: "green" | "red" | "" (muted/default)
function pill(label, kind = "") {
  const cls = kind ? `pill pill-${kind}` : "pill";
  return `<span class="${cls}">${esc(label)}</span>`;
}

const FOUNDER_NAV = [
  ["dashboard", "/dashboard", "Dashboard"],
  ["freelancers", "/freelancers", "Freelancers"],
  ["clients", "/clients", "Clients"],
  ["leads", "/leads", "Leads"],
  ["revenue", "/revenue", "Revenue"],
  ["audit", "/audit", "Audit"],
  ["retention", "/retention", "Retention"],
  ["errors", "/errors", "Errors"],
  ["security", "/security", "Security"],
];
const FREELANCER_NAV = [
  ["log", "/log", "This Week"],
  ["history", "/log/history", "History"],
  ["security", "/security", "Security"],
];

function layout({ title, user, active, body, theme = "dark" }) {
  const safeTheme = theme === "light" ? "light" : "dark";
  const themeLabel = safeTheme === "dark" ? "Dark" : "Light";
  const navList = user ? (user.role === "founder" ? FOUNDER_NAV : FREELANCER_NAV) : [];

  const desktopLinks = navList
    .map(([key, href, label]) => `<a href="${href}" class="navlink${active === key ? " on" : ""}">${esc(label)}</a>`)
    .join("");
  const mobileLinks = navList
    .map(([key, href, label]) => `<a href="${href}" class="mobilelink${active === key ? " on" : ""}">${esc(label)}</a>`)
    .join("");

  const brand = `<div class="brandwrap"><span class="brand">Catalyst 7</span><span class="brand-sub">KPI</span></div>`;
  const modeToggle = `<a href="/theme/toggle" class="mode-toggle">${themeLabel}</a>`;

  const header = user
    ? `
    <input type="checkbox" id="navtoggle" class="hamburger-toggle" />
    <header class="topnav">
      ${brand}
      <nav class="links">${desktopLinks}</nav>
      <div class="navright">
        <span class="who-name">${esc(user.name)}</span>
        ${modeToggle}
        <a href="/logout" class="mode-toggle">Log out</a>
        <label for="navtoggle" class="hamburger-label" aria-label="Menu">
          <span class="glyph-open">&#9776;</span><span class="glyph-close">&#10005;</span>
        </label>
      </div>
    </header>
    <nav class="mobile-menu">${mobileLinks}<a href="/logout" class="mobilelink">Log out</a></nav>`
    : `
    <header class="authbar">
      ${brand}
      ${modeToggle}
    </header>`;

  return `<!doctype html>
<html lang="en" data-theme="${safeTheme}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(title)} &middot; Catalyst 7 KPI</title>
<style>
:root {
  --bg: #0D0D0D; --text: #F5EDD8; --text-muted: #9c9686;
  --panel: #171717; --panel-2: #1d1d1b; --border: #2c2c2a;
  --red: #C1272D; --red-text: #E2726B; --red-tint-bg: rgba(193,39,45,0.16);
  --green: #5FAE7E; --green-text: #7FC79A; --green-tint-bg: rgba(95,174,126,0.16);
  --on-red: #F5EDD8; --input-bg: #141412;
  --font: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --font-mono: ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sp-1: 4px; --sp-2: 8px; --sp-3: 12px; --sp-4: 16px; --sp-5: 24px; --sp-6: 32px; --sp-7: 48px;
  --radius: 6px; --radius-pill: 999px;
}
html[data-theme="light"] {
  --bg: #F5EDD8; --text: #0D0D0D; --text-muted: #8a806a;
  --panel: #FFFCF5; --panel-2: #F7F0DC; --border: #DDD0AF;
  --red: #C1272D; --red-text: #C1272D; --red-tint-bg: rgba(193,39,45,0.08);
  --green: #2F7A4D; --green-text: #2F7A4D; --green-tint-bg: rgba(47,122,77,0.10);
  --on-red: #F5EDD8; --input-bg: #FFFFFF;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);-webkit-font-smoothing:antialiased}
a{color:inherit}
::placeholder{color:var(--text-muted);opacity:.7}

/* header / nav */
.topnav{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 32px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:10}
.authbar{display:flex;align-items:center;justify-content:space-between;padding:16px 32px;border-bottom:1px solid var(--border)}
.brandwrap{display:flex;align-items:baseline;gap:8px;flex-shrink:0}
.brand{font-weight:700;font-size:16px;letter-spacing:-0.01em;color:var(--red)}
.brand-sub{font-size:11px;color:var(--text-muted);letter-spacing:.1em;text-transform:uppercase}
nav.links{display:flex;gap:2px;flex-wrap:wrap}
.navlink{padding:8px 12px;font-size:13px;font-weight:500;color:var(--text-muted);text-decoration:none;border-radius:var(--radius);white-space:nowrap}
.navlink.on{font-weight:600;color:var(--text);background:var(--panel-2)}
.navright{display:flex;align-items:center;gap:8px;flex-shrink:0}
.who-name{font-size:12px;color:var(--text-muted);white-space:nowrap}
.mode-toggle{font-size:12px;font-weight:600;padding:7px 12px;border-radius:var(--radius-pill);border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer;text-decoration:none;white-space:nowrap}
.hamburger-toggle{display:none}
.hamburger-label{display:none;font-size:16px;width:34px;height:34px;border-radius:var(--radius);border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer;align-items:center;justify-content:center;flex-shrink:0}
.glyph-close{display:none}
.hamburger-toggle:checked ~ .topnav .glyph-open{display:none}
.hamburger-toggle:checked ~ .topnav .glyph-close{display:inline}
.mobile-menu{display:none;flex-direction:column;background:var(--bg);border-bottom:1px solid var(--border)}
.mobilelink{padding:13px 16px;font-size:14px;font-weight:500;color:var(--text-muted);text-decoration:none;border-bottom:1px solid var(--border)}
.mobilelink.on{font-weight:600;color:var(--text)}
@media (max-width:859px){
  nav.links{display:none}
  .who-name{display:none}
  .hamburger-label{display:flex}
  /* Scoped to the mobile breakpoint on purpose: if the checkbox is left
     checked and the viewport widens (phone rotated to landscape, desktop
     window dragged wider), an unscoped rule would leave the mobile menu
     stuck open underneath the restored desktop nav. */
  .hamburger-toggle:checked ~ .mobile-menu{display:flex}
}
@media (max-width:640px){
  .topnav, .authbar{padding:14px 16px}
}

/* main / page head */
main{max-width:1200px;margin:0 auto;padding:32px 32px 72px}
main.authmain{max-width:400px;padding:60px 16px}
@media (max-width:640px){ main{padding:20px 16px 60px} }
.page-head{margin-bottom:var(--sp-5)}
.page-title{font-size:22px;font-weight:700;letter-spacing:-0.01em}
.page-sub{font-size:13px;color:var(--text-muted);margin-top:4px}
.page-head-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:var(--sp-5)}
h2.section-label{font-size:13px;font-weight:600;margin:0 0 12px}

/* metrics grid (dashboard) */
.metrics-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:var(--sp-6)}
.metric-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.metric-label{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--text-muted)}
.metric-value{font-size:27px;font-weight:700;font-family:var(--font-mono);letter-spacing:-0.01em;margin-top:10px}
.metric-foot{display:flex;align-items:center;gap:7px;margin-top:11px;flex-wrap:wrap}
.metric-delta{font-size:12.5px;font-weight:700;font-family:var(--font-mono)}
.metric-delta.up{color:var(--green-text)}
.metric-delta.down{color:var(--red-text)}
.metric-delta.flat{color:var(--text-muted)}
.metric-sub{font-size:12px;color:var(--text-muted)}

.tables-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}

/* panels / tables */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:var(--sp-5)}
.panel:last-child{margin-bottom:0}
.panel-head{font-size:13px;font-weight:600;padding:14px 16px;border-bottom:1px solid var(--border)}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 16px;font-size:10.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-muted);border-bottom:1px solid var(--border);white-space:nowrap}
th.right{text-align:right}
td{padding:10px 16px;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
td.strong{font-weight:600}
td.muted{color:var(--text-muted)}
td.mono{font-family:var(--font-mono)}
td.detail{color:var(--text-muted)}
td.right{text-align:right}
td.nowrap{white-space:nowrap}

/* pills */
.pill{display:inline-block;padding:4px 10px;border-radius:var(--radius-pill);font-size:12px;font-weight:600;border:1px solid var(--border);background:var(--panel-2);color:var(--text-muted);text-transform:capitalize}
.pill-green{border-color:var(--green-text);background:var(--green-tint-bg);color:var(--green-text)}
.pill-red{border-color:var(--red-text);background:var(--red-tint-bg);color:var(--red-text)}

/* buttons */
.btn{font-size:13px;font-weight:600;padding:10px 16px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer;text-decoration:none;display:inline-block;font-family:inherit;line-height:1.2}
.btn-primary{border-color:var(--red);background:var(--red);color:var(--on-red)}
.btn-danger{border-color:var(--red-text);color:var(--red-text);background:transparent}
.btn-sm{font-size:12.5px;padding:7px 12px}
.btn[disabled]{opacity:.5;cursor:default}
.row-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.row-actions form{display:inline}

/* forms */
form.plain{margin:0}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;padding:16px}
.field{display:flex;flex-direction:column;gap:6px}
.field.wide{grid-column:1/-1}
.field label{font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em}
input, select, textarea{font-size:13px;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--input-bg);color:var(--text);font-family:var(--font);width:100%}
textarea{min-height:70px;resize:vertical}
.form-foot{display:flex;justify-content:flex-end;gap:8px;padding:14px 16px;border-top:1px solid var(--border)}

/* collapsible add-forms -- pure CSS, no JS */
.form-toggle{display:none}
.add-panel{display:none}
.form-toggle:checked ~ .add-panel{display:block}
.toggle-open{display:inline}
.toggle-close{display:none}
.form-toggle:checked ~ .page-head-row .toggle-open{display:none}
.form-toggle:checked ~ .page-head-row .toggle-close{display:inline}

/* stage select (leads) -- colour follows value */
select.stage-select{width:auto;font-size:12px;font-weight:600;padding:6px 10px;border-radius:var(--radius-pill);cursor:pointer;text-transform:capitalize}
select.stage-won{border-color:var(--green-text);background:var(--green-tint-bg);color:var(--green-text)}
select.stage-lost{border-color:var(--red-text);background:var(--red-tint-bg);color:var(--red-text)}

/* messages */
.msg{padding:12px 14px;border-radius:var(--radius);margin-bottom:18px;font-size:14px;border:1px solid var(--border)}
.msg-error{background:var(--red-tint-bg);color:var(--red-text);border-color:var(--red-text)}
.msg-ok{background:var(--green-tint-bg);color:var(--green-text);border-color:var(--green-text)}

.empty{color:var(--text-muted);font-size:14px;padding:24px;text-align:center}
.hint{color:var(--text-muted);font-size:12px}
.mono-box{font-family:var(--font-mono);font-size:12px;background:var(--input-bg);padding:8px 10px;border-radius:var(--radius);word-break:break-all;border:1px solid var(--border);display:block;margin:8px 0}

/* auth card */
.authcard{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:28px}
.authcard h1{font-size:20px;font-weight:700;letter-spacing:-0.01em;margin:0 0 6px}
.authcard .lead{font-size:13px;color:var(--text-muted);margin-bottom:24px}
.authcard .btn-primary{width:100%;margin-top:6px;text-align:center;padding:11px 16px}
.authcard .field{margin-bottom:14px}
.authcard .helper{font-size:12.5px;color:var(--text-muted);margin-top:16px}

/* security panel */
.security-status{margin-bottom:10px}
.security-body{padding:24px}
.security-copy{font-size:14px;color:var(--text-muted);line-height:1.6;max-width:480px;margin-bottom:20px}
.setup-grid{display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start}
.security-section{border-top:1px solid var(--border);margin-top:24px;padding-top:24px}
.security-section:first-child{border-top:none;margin-top:0;padding-top:0}
h3.sub-label{font-size:13px;font-weight:600;margin:0 0 8px}

/* federated sign-in */
.btn-google{width:100%;text-align:center;margin-top:6px;padding:11px 16px;display:flex;align-items:center;justify-content:center;gap:9px}
.gmark{width:16px;height:16px;flex-shrink:0}
.or-divider{display:flex;align-items:center;gap:12px;margin:20px 0;color:var(--text-muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.or-divider::before,.or-divider::after{content:"";flex:1;height:1px;background:var(--border)}

/* backup codes */
.codes-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:14px 0}
.code-chip{font-family:var(--font-mono);font-size:13.5px;letter-spacing:.04em;background:var(--input-bg);border:1px solid var(--border);border-radius:var(--radius);padding:9px 12px;text-align:center}
.code-chip.spent{opacity:.45;text-decoration:line-through}
.codes-warn{font-size:13px;line-height:1.6;max-width:520px}
</style>
</head>
<body>
${header}
<main${user ? "" : ' class="authmain"'}>
${body}
</main>
</body>
</html>`;
}

// Google's mark, inlined as an SVG so the login page still makes zero
// external requests (and the CSP can keep default-src 'none').
const GOOGLE_MARK = `<svg class="gmark" viewBox="0 0 48 48" aria-hidden="true" focusable="false"><path fill="#4285F4" d="M45.1 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h11.8c-.5 2.7-2 5-4.4 6.6v5.5h7.1c4.1-3.8 6.6-9.4 6.6-16.1z"/><path fill="#34A853" d="M24 46c6 0 11-2 14.6-5.4l-7.1-5.5c-2 1.3-4.5 2.1-7.5 2.1-5.8 0-10.7-3.9-12.4-9.1H4.3v5.7C7.9 41 15.4 46 24 46z"/><path fill="#FBBC05" d="M11.6 28.1c-.4-1.3-.7-2.7-.7-4.1s.2-2.8.7-4.1v-5.7H4.3C2.8 17.1 2 20.4 2 24s.8 6.9 2.3 9.8l7.3-5.7z"/><path fill="#EA4335" d="M24 10.8c3.3 0 6.2 1.1 8.5 3.3l6.3-6.3C35 4.3 30 2 24 2 15.4 2 7.9 7 4.3 14.2l7.3 5.7c1.7-5.2 6.6-9.1 12.4-9.1z"/></svg>`;

// ---------- Auth pages ----------
export function loginPage({ error, theme, googleEnabled = false } = {}) {
  const google = googleEnabled
    ? `
      <a href="/auth/google" class="btn btn-google">${GOOGLE_MARK}<span>Continue with Google</span></a>
      <div class="or-divider">or</div>`
    : "";

  return layout({
    title: "Log in",
    theme,
    body: `
    <div class="authcard">
      <h1>Sign in</h1>
      <p class="lead">Enter your Catalyst 7 credentials.</p>
      ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
      ${google}
      <form class="plain" method="post" action="/login">
        <div class="field"><label>Email</label><input type="email" name="email" required placeholder="you@catalyst7.co.za" /></div>
        <div class="field"><label>Password</label><input type="password" name="password" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" /></div>
        <button type="submit" class="btn btn-primary">Continue</button>
      </form>
      <div class="helper">Forgot password? Ask a founder to reset it from Freelancers or Clients.</div>
    </div>`,
  });
}

export function totpVerifyPage({ error, theme } = {}) {
  return layout({
    title: "Verify it's you",
    theme,
    body: `
    <div class="authcard">
      <h1>Enter your code</h1>
      <p class="lead">Open your authenticator app and enter the 6-digit code to finish signing in.</p>
      ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
      <form class="plain" method="post" action="/login/2fa">
        <div class="field"><label>Authentication or backup code</label><input name="code" autocomplete="one-time-code" maxlength="12" required autofocus placeholder="000000" /></div>
        <button type="submit" class="btn btn-primary">Verify</button>
      </form>
      <div class="helper">Lost your device? Use one of the backup codes you saved when you turned 2FA on &mdash; each works once. No backup codes left? A founder can disable 2FA on your account.</div>
    </div>`,
  });
}

export function setupPage({ token, name, error, theme }) {
  return layout({
    title: "Set your password",
    theme,
    body: `
    <div class="authcard">
      <h1>Set your password</h1>
      <p class="lead">Welcome, ${esc(name)}. This is your first sign-in &mdash; choose a password to secure your account.</p>
      ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
      <form class="plain" method="post" action="/setup/${esc(token)}">
        <div class="field"><label>New password (min 8 characters)</label><input type="password" name="password" minlength="8" required autofocus placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" /></div>
        <div class="field"><label>Confirm password</label><input type="password" name="confirm" minlength="8" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" /></div>
        <button type="submit" class="btn btn-primary">Set password &amp; continue</button>
      </form>
    </div>`,
  });
}

// ---------- Security / 2FA self-service ----------
export function securityPage({
  user,
  csrf,
  pendingSecret,
  pendingUri,
  error,
  message,
  theme,
  newBackupCodes = null,
  backupCodesLeft = 0,
  googleLinked = false,
  googleEnabled = false,
}) {
  let stateBody;
  if (user.totp_enabled) {
    const codesBlock = newBackupCodes
      ? `
      <div class="msg msg-ok codes-warn">
        <strong>Save these now — this is the only time they'll be shown.</strong><br />
        Each code works once, in place of your authenticator app. Print them or put them in a password manager; don't leave them in this browser tab.
      </div>
      <div class="codes-grid">${newBackupCodes.map((c) => `<div class="code-chip">${esc(c)}</div>`).join("")}</div>`
      : `<div class="security-copy" style="margin-bottom:14px">${
          backupCodesLeft > 0
            ? `You have <strong>${backupCodesLeft}</strong> unused backup code${backupCodesLeft === 1 ? "" : "s"}. Each one signs you in once if you lose your authenticator.`
            : `You have <strong>no unused backup codes</strong>. If you lose your authenticator you'll need another founder to clear 2FA for you. Generate a set now.`
        }</div>`;

    stateBody = `
      <div class="security-section">
        <div class="security-status">${pill("2FA on", "green")}</div>
        <div class="security-copy">Two-factor authentication is protecting this account. You'll be asked for a code from your authenticator app each time you sign in.</div>
        <form method="post" action="/security/2fa/disable">
          ${csrfField(csrf)}
          <button type="submit" class="btn btn-danger">Disable 2FA</button>
        </form>
      </div>
      <div class="security-section">
        <h3 class="sub-label">Backup codes</h3>
        ${codesBlock}
        <form method="post" action="/security/2fa/backup-codes">
          ${csrfField(csrf)}
          <button type="submit" class="btn">${newBackupCodes || backupCodesLeft ? "Regenerate backup codes" : "Generate backup codes"}</button>
        </form>
        <div class="hint" style="margin-top:8px">Regenerating immediately invalidates every code from the previous set.</div>
      </div>`;
  } else if (pendingSecret) {
    stateBody = `
      <div class="security-status">${pill("Setup in progress")}</div>
      <div class="setup-grid">
        <div style="min-width:220px;flex:1">
          <div class="hint" style="margin-bottom:6px">Scan or manually enter this secret into your authenticator app (Google Authenticator, Authy, 1Password, etc):</div>
          <span class="mono-box">${esc(pendingSecret)}</span>
          <div class="hint">Manual URI: ${esc(pendingUri)}</div>
        </div>
        <form method="post" action="/security/2fa/confirm" style="min-width:220px;flex:1">
          ${csrfField(csrf)}
          <div class="field" style="margin-bottom:10px"><label>Code from your app</label><input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required placeholder="000000" /></div>
          <button type="submit" class="btn btn-primary">Confirm &amp; enable</button>
        </form>
      </div>`;
  } else {
    stateBody = `
      <div class="security-status">${pill("2FA off")}</div>
      <div class="security-copy">Two-factor authentication is not enabled on this account. Turn it on to require a code from your authenticator app when signing in.</div>
      <form method="post" action="/security/2fa/start">
        ${csrfField(csrf)}
        <button type="submit" class="btn btn-primary">Enable two-factor authentication</button>
      </form>`;
  }

  return layout({
    user,
    active: "security",
    title: "Security",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Security</div>
      <div class="page-sub">${esc(user.name)} &middot; ${esc(user.email)}</div>
    </div>
    ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
    ${message ? `<div class="msg msg-ok">${esc(message)}</div>` : ""}
    <div class="panel"><div class="security-body">${stateBody}</div></div>
    ${
      googleEnabled
        ? `<div class="panel"><div class="security-body">
            <h3 class="sub-label">Google sign-in</h3>
            <div class="security-status">${googleLinked ? pill("linked", "green") : pill("not linked")}</div>
            <div class="security-copy">${
              googleLinked
                ? `This account is linked to the Google account for ${esc(user.email)}, so you can sign in with either Google or your password. Two-factor still applies to both.`
                : `You can sign in with Google using ${esc(user.email)} — the link is made automatically the first time you use "Continue with Google" on the sign-in page. Your password keeps working either way.`
            }</div>
          </div></div>`
        : ""
    }
  `,
  });
}

// ---------- Founder: Dashboard ----------
export function dashboardPage({ user, data, theme }) {
  const h = delta(data.hoursThis, data.hoursPrev);
  const r = delta(data.revThis, data.revPrev);
  const revRows = data.revByType
    .map(
      (t) => `<tr><td class="nowrap" style="text-transform:capitalize">${esc(t.type)}</td><td class="mono">${money(t.total)}</td></tr>`
    )
    .join("");
  const stageRows = data.leadsByStage
    .map(
      (s) => `<tr><td class="nowrap" style="text-transform:capitalize">${esc(s.stage)}</td><td class="mono">${s.n}</td><td class="mono right">${money(s.val)}</td></tr>`
    )
    .join("");
  const missingRows = data.missingFreelancers.length
    ? data.missingFreelancers.map((f) => pill(f.name, "red")).join(" ")
    : pill("everyone's logged", "green");

  return layout({
    user,
    active: "dashboard",
    title: "Dashboard",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Dashboard</div>
      <div class="page-sub">Week of ${esc(data.weekStart)} &middot; compared against week of ${esc(data.prevWeekStart)}</div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-label">Freelancer hours</div>
        <div class="metric-value">${Number(data.hoursThis).toFixed(1)}</div>
        <div class="metric-foot"><span class="metric-delta ${h.cls}">${h.text}</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Revenue this week</div>
        <div class="metric-value">${money(data.revThis)}</div>
        <div class="metric-foot"><span class="metric-delta ${r.cls}">${r.text}</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Pipeline value (open leads)</div>
        <div class="metric-value">${money(data.pipelineValue)}</div>
        <div class="metric-foot"><span class="metric-sub">${data.newLeads} new this wk</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Deals won this week</div>
        <div class="metric-value">${data.wonThis.n}</div>
        <div class="metric-foot"><span class="metric-delta up">${money(data.wonThis.val)}</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Active clients</div>
        <div class="metric-value">${data.activeClients}</div>
        <div class="metric-foot"><span class="metric-sub">${data.newClients} new this wk</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Log compliance</div>
        <div class="metric-value">${data.submittedCount}/${data.activeFreelancerCount}</div>
        <div class="metric-foot"><span class="metric-sub">freelancers logged</span></div>
      </div>
    </div>

    <div class="tables-grid">
      <div class="panel">
        <div class="panel-head">Revenue by type</div>
        <div class="table-wrap">
          ${
            revRows
              ? `<table><thead><tr><th>Type</th><th>This week</th></tr></thead><tbody>${revRows}</tbody></table>`
              : `<div class="empty">No revenue logged yet this week.</div>`
          }
        </div>
      </div>
      <div class="panel">
        <div class="panel-head">Open pipeline by stage</div>
        <div class="table-wrap">
          ${
            stageRows
              ? `<table><thead><tr><th>Stage</th><th>Deals</th><th class="right">Value</th></tr></thead><tbody>${stageRows}</tbody></table>`
              : `<div class="empty">No open leads.</div>`
          }
        </div>
      </div>
    </div>

    <h2 class="section-label" style="margin-top:32px">Haven't logged this week</h2>
    <div style="display:flex;flex-wrap:wrap;gap:8px">${missingRows}</div>
  `,
  });
}

// ---------- Founder: Freelancers ----------
export function freelancersPage({ user, freelancers, inviteLink, csrf, theme }) {
  const rows = freelancers
    .map(
      (f) => `<tr>
      <td class="strong">${esc(f.name)}</td>
      <td>${esc(f.role_title || "—")}</td>
      <td class="mono">${esc(f.rate_type)}${f.rate_amount ? " &middot; " + money(f.rate_amount) : ""}</td>
      <td>${f.active ? pill("active", "green") : pill("inactive")}</td>
      <td class="right">
        <div class="row-actions">
          <form method="post" action="/freelancers/${f.id}/invite">${csrfField(csrf)}<button type="submit" class="btn btn-sm">Invite link</button></form>
          <form method="post" action="/freelancers/${f.id}/toggle">${csrfField(csrf)}<button type="submit" class="btn btn-sm">${f.active ? "Deactivate" : "Activate"}</button></form>
        </div>
      </td>
    </tr>`
    )
    .join("");

  return layout({
    user,
    active: "freelancers",
    title: "Freelancers",
    theme,
    body: `
    <input type="checkbox" id="add-toggle" class="form-toggle" />
    <div class="page-head-row">
      <div>
        <div class="page-title">Freelancers</div>
        <div class="page-sub">${freelancers.length} ${freelancers.length === 1 ? "freelancer" : "freelancers"}</div>
      </div>
      <label for="add-toggle" class="btn btn-primary"><span class="toggle-open">Add freelancer</span><span class="toggle-close">Close</span></label>
    </div>

    ${
      inviteLink
        ? `<div class="msg msg-ok">Invite link generated. Send this to the freelancer (WhatsApp, email &mdash; your choice, it's single-use):<span class="mono-box">${esc(inviteLink)}</span></div>`
        : ""
    }

    <div class="panel add-panel">
      <div class="panel-head">Add freelancer</div>
      <form class="plain" method="post" action="/freelancers">
        ${csrfField(csrf)}
        <div class="form-grid">
          <div class="field"><label>Name</label><input name="name" required placeholder="Naledi Khumalo" /></div>
          <div class="field"><label>Email</label><input name="email" type="email" placeholder="naledi@example.com" /></div>
          <div class="field"><label>Role / title</label><input name="role_title" placeholder="Designer" /></div>
          <div class="field"><label>Rate type</label>
            <select name="rate_type"><option value="hourly">Hourly</option><option value="project">Project</option><option value="retainer">Retainer</option></select>
          </div>
          <div class="field"><label>Rate (R)</label><input name="rate_amount" type="number" step="0.01" placeholder="650" /></div>
        </div>
        <div class="form-foot">
          <label for="add-toggle" class="btn">Cancel</label>
          <button type="submit" class="btn btn-primary">Add freelancer</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Name</th><th>Role</th><th>Rate</th><th>Status</th><th class="right">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">No freelancers yet.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Clients ----------
export function clientsPage({ user, clients, csrf, theme }) {
  const rows = clients
    .map(
      (c) => `<tr>
      <td class="strong">${esc(c.name)}</td>
      <td>${c.status === "active" ? pill("active", "green") : pill("past")}</td>
      <td>${esc(c.contact_name || "—")}</td>
      <td class="muted">${esc(c.source || "—")}</td>
      <td class="right">
        <form method="post" action="/clients/${c.id}/toggle" class="row-actions">${csrfField(csrf)}<button type="submit" class="btn btn-sm">${c.status === "active" ? "Mark past" : "Mark active"}</button></form>
      </td>
    </tr>`
    )
    .join("");

  return layout({
    user,
    active: "clients",
    title: "Clients",
    theme,
    body: `
    <input type="checkbox" id="add-toggle" class="form-toggle" />
    <div class="page-head-row">
      <div>
        <div class="page-title">Clients</div>
        <div class="page-sub">${clients.length} ${clients.length === 1 ? "client" : "clients"}</div>
      </div>
      <label for="add-toggle" class="btn btn-primary"><span class="toggle-open">Add client</span><span class="toggle-close">Close</span></label>
    </div>

    <div class="panel add-panel">
      <div class="panel-head">Add client</div>
      <form class="plain" method="post" action="/clients">
        ${csrfField(csrf)}
        <div class="form-grid">
          <div class="field"><label>Client name</label><input name="name" required placeholder="Umlazi Foods" /></div>
          <div class="field"><label>Contact name</label><input name="contact_name" placeholder="Zanele Buthelezi" /></div>
          <div class="field"><label>Contact email</label><input name="contact_email" type="email" placeholder="zanele@umlazifoods.co.za" /></div>
          <div class="field"><label>Source</label><input name="source" placeholder="referral, outbound..." /></div>
        </div>
        <div class="form-foot">
          <label for="add-toggle" class="btn">Cancel</label>
          <button type="submit" class="btn btn-primary">Add client</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Client</th><th>Status</th><th>Contact</th><th>Source</th><th class="right">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">No clients yet.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Leads ----------
const STAGES = ["new", "contacted", "qualified", "proposal", "won", "lost"];
export function leadsPage({ user, leads, csrf, theme }) {
  const rows = leads
    .map((l) => {
      const opts = STAGES.map((s) => `<option value="${s}" ${s === l.stage ? "selected" : ""}>${s}</option>`).join("");
      const selCls = l.stage === "won" ? "stage-won" : l.stage === "lost" ? "stage-lost" : "";
      return `<tr>
      <td class="strong">${esc(l.name)}${l.company ? `<br/><span class="hint">${esc(l.company)}</span>` : ""}</td>
      <td class="muted">${esc(l.owner || "—")}</td>
      <td class="mono">${l.value_estimate ? money(l.value_estimate) : "—"}</td>
      <td class="right">
        <form method="post" action="/leads/${l.id}/stage" class="plain">
          ${csrfField(csrf)}
          <select name="stage" class="stage-select ${selCls}" onchange="this.form.submit()">${opts}</select>
        </form>
      </td>
    </tr>`;
    })
    .join("");

  return layout({
    user,
    active: "leads",
    title: "Leads",
    theme,
    body: `
    <input type="checkbox" id="add-toggle" class="form-toggle" />
    <div class="page-head-row">
      <div>
        <div class="page-title">Leads</div>
        <div class="page-sub">${leads.length} ${leads.length === 1 ? "lead" : "leads"}</div>
      </div>
      <label for="add-toggle" class="btn btn-primary"><span class="toggle-open">Add lead</span><span class="toggle-close">Close</span></label>
    </div>

    <div class="panel add-panel">
      <div class="panel-head">Add lead</div>
      <form class="plain" method="post" action="/leads">
        ${csrfField(csrf)}
        <div class="form-grid">
          <div class="field"><label>Name</label><input name="name" required placeholder="Zanele Buthelezi" /></div>
          <div class="field"><label>Company</label><input name="company" placeholder="Rivonia Retail Group" /></div>
          <div class="field"><label>Value estimate (R)</label><input name="value_estimate" type="number" step="0.01" placeholder="25000" /></div>
          <div class="field"><label>Owner</label><input name="owner" placeholder="Thembalethu, Somila, Lethu..." /></div>
          <div class="field"><label>Source</label><input name="source" placeholder="referral, outbound..." /></div>
        </div>
        <div class="form-foot">
          <label for="add-toggle" class="btn">Cancel</label>
          <button type="submit" class="btn btn-primary">Add lead</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Lead</th><th>Owner</th><th>Value</th><th class="right">Stage</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">No leads yet.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Revenue ----------
export function revenuePage({ user, entries, clients, csrf, theme }) {
  const clientOpts = clients.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join("");
  const rows = entries
    .map((r) => {
      const kind = r.invoice_status === "paid" ? "green" : r.invoice_status === "overdue" ? "red" : "";
      return `<tr>
      <td class="nowrap">${esc(r.week_start)}</td>
      <td class="strong">${esc(r.client_name || "—")}</td>
      <td class="muted" style="text-transform:capitalize">${esc(r.type)}</td>
      <td class="mono">${money(r.amount)}</td>
      <td class="right">${pill(r.invoice_status, kind)}</td>
    </tr>`;
    })
    .join("");

  return layout({
    user,
    active: "revenue",
    title: "Revenue",
    theme,
    body: `
    <input type="checkbox" id="add-toggle" class="form-toggle" />
    <div class="page-head-row">
      <div>
        <div class="page-title">Revenue</div>
        <div class="page-sub">${entries.length} ${entries.length === 1 ? "entry" : "entries"}</div>
      </div>
      <label for="add-toggle" class="btn btn-primary"><span class="toggle-open">Add entry</span><span class="toggle-close">Close</span></label>
    </div>

    <div class="panel add-panel">
      <div class="panel-head">Add revenue entry</div>
      <form class="plain" method="post" action="/revenue">
        ${csrfField(csrf)}
        <div class="form-grid">
          <div class="field"><label>Week starting (Mon)</label><input name="week_start" type="date" required /></div>
          <div class="field"><label>Client</label><select name="client_id"><option value="">—</option>${clientOpts}</select></div>
          <div class="field"><label>Amount (R)</label><input name="amount" type="number" step="0.01" required placeholder="12400" /></div>
          <div class="field"><label>Type</label>
            <select name="type"><option value="project">Project</option><option value="retainer">Retainer</option><option value="platform_fee">Platform fee</option><option value="equity">Equity</option><option value="other">Other</option></select>
          </div>
          <div class="field"><label>Invoice status</label>
            <select name="invoice_status"><option value="invoiced">Invoiced</option><option value="paid">Paid</option><option value="overdue">Overdue</option></select>
          </div>
        </div>
        <div class="form-foot">
          <label for="add-toggle" class="btn">Cancel</label>
          <button type="submit" class="btn btn-primary">Add entry</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Week</th><th>Client</th><th>Type</th><th>Amount</th><th class="right">Invoice</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">No revenue logged yet.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Freelancer: weekly log ----------
export function logPage({ user, weekStart, entry, freelancer, csrf, theme }) {
  return layout({
    user,
    active: "log",
    title: "This week",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Week of ${esc(weekStart)}</div>
      <div class="page-sub">${esc(freelancer.name)} &middot; ${esc(freelancer.role_title || "")}</div>
    </div>
    <div class="panel">
      <form class="plain" method="post" action="/log">
        ${csrfField(csrf)}
        <div class="form-grid" style="grid-template-columns:1fr">
          <div class="field"><label>Hours worked this week</label><input name="hours" type="number" step="0.25" min="0" value="${entry ? entry.hours : ""}" required /></div>
          <div class="field"><label>Deliverables completed</label><textarea name="deliverables">${esc(entry ? entry.deliverables : "")}</textarea></div>
          <div class="field"><label>Status</label>
            <select name="status">
              <option value="on_track" ${entry && entry.status === "on_track" ? "selected" : ""}>On track</option>
              <option value="blocked" ${entry && entry.status === "blocked" ? "selected" : ""}>Blocked</option>
              <option value="delayed" ${entry && entry.status === "delayed" ? "selected" : ""}>Delayed</option>
            </select>
          </div>
          <div class="field"><label>Notes</label><textarea name="notes">${esc(entry ? entry.notes : "")}</textarea></div>
        </div>
        <div class="form-foot">
          <button type="submit" class="btn btn-primary">${entry ? "Update this week's log" : "Submit this week's log"}</button>
        </div>
      </form>
    </div>
  `,
  });
}

export function historyPage({ user, rows, theme }) {
  const trs = rows
    .map(
      (r) => `<tr>
      <td class="nowrap">${esc(r.week_start)}</td>
      <td class="mono">${r.hours}</td>
      <td class="muted" style="text-transform:capitalize">${esc(r.status)}</td>
      <td class="detail">${esc(r.deliverables || "—")}</td>
    </tr>`
    )
    .join("");
  return layout({
    user,
    active: "history",
    title: "History",
    theme,
    body: `
    <div class="page-head"><div class="page-title">Your history</div></div>
    <div class="panel">
      <div class="table-wrap">
        ${
          trs
            ? `<table><thead><tr><th>Week</th><th>Hours</th><th>Status</th><th>Deliverables</th></tr></thead><tbody>${trs}</tbody></table>`
            : `<div class="empty">No entries yet.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Audit log ----------
export function auditPage({ user, rows, theme }) {
  const trs = rows
    .map((r) => {
      const kind = r.action === "delete" ? "red" : r.action && r.action.includes("create") ? "green" : "";
      return `<tr>
      <td class="mono muted nowrap">${esc(r.created_at)}</td>
      <td class="strong nowrap">${esc(r.user_name)}</td>
      <td class="nowrap">${pill(r.action, kind)}</td>
      <td class="muted nowrap">${esc(r.entity_type || "—")}${r.entity_id ? " #" + r.entity_id : ""}</td>
      <td class="detail">${esc(r.detail || "—")}</td>
    </tr>`;
    })
    .join("");
  return layout({
    user,
    active: "audit",
    title: "Audit log",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Audit log</div>
      <div class="page-sub">Who changed what, and when. Last 100 actions.</div>
    </div>
    <div class="panel">
      <div class="table-wrap">
        ${
          trs
            ? `<table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Entity</th><th>Detail</th></tr></thead><tbody>${trs}</tbody></table>`
            : `<div class="empty">No activity logged yet.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Error log ----------
export function errorsPage({ user, rows, theme }) {
  const trs = rows
    .map(
      (r) => `<tr>
      <td class="mono muted nowrap">${esc(r.created_at)}</td>
      <td class="strong nowrap">${esc(r.path)}</td>
      <td class="detail">${esc(r.message)}</td>
    </tr>`
    )
    .join("");
  return layout({
    user,
    active: "errors",
    title: "Errors",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Error log</div>
      <div class="page-sub">Unhandled application errors, last 100 &middot; read-only. Cloudflare's own Workers Analytics (dashboard &rarr; your worker &rarr; Metrics) covers request-level performance and uptime on top of this.</div>
    </div>
    <div class="panel">
      <div class="table-wrap">
        ${
          trs
            ? `<table><thead><tr><th>When</th><th>Path</th><th>Message</th></tr></thead><tbody>${trs}</tbody></table>`
            : `<div class="empty">No errors logged. Good sign.</div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Retention review ----------
export function retentionPage({ user, flags, csrf, theme }) {
  const rows = flags
    .map(
      (f) => `<tr>
      <td class="muted nowrap" style="text-transform:capitalize">${esc(f.entity_type)}</td>
      <td class="strong">${esc(f.label)}</td>
      <td class="detail">${esc(f.reason)}</td>
      <td class="mono muted nowrap">${esc(f.flagged_at)}</td>
      <td class="right">
        <div class="row-actions">
          <form method="post" action="/retention/${f.id}/resolve">
            ${csrfField(csrf)}
            <input type="hidden" name="decision" value="keep" />
            <button type="submit" class="btn btn-sm">Keep</button>
          </form>
          <form method="post" action="/retention/${f.id}/resolve" onsubmit="return confirm('Erase this record\\'s personal info? This cannot be undone.');">
            ${csrfField(csrf)}
            <input type="hidden" name="decision" value="erase" />
            <button type="submit" class="btn btn-sm btn-danger">Erase personal info</button>
          </form>
        </div>
      </td>
    </tr>`
    )
    .join("");
  return layout({
    user,
    active: "retention",
    title: "Retention review",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Retention review</div>
      <div class="page-sub">Flagged automatically on the 1st of each month: lost leads and inactive freelancers with no activity in 365+ days. "Erase" clears the name/contact fields but keeps any linked financial records intact (so past revenue/hours history stays accurate) &mdash; it never deletes the row outright.</div>
    </div>
    <div class="panel">
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Type</th><th>Record</th><th>Reason</th><th>Flagged</th><th class="right">Action</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">Nothing awaiting review.</div>`
        }
      </div>
    </div>
  `,
  });
}

export function errorPage(message, status = 400, theme = "dark") {
  return layout({
    title: "Error",
    theme,
    body: `<div class="msg msg-error">${esc(message)}</div><p><a href="/" class="btn btn-sm" style="margin-top:8px">Back</a></p>`,
  });
}
