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

// Every mutating form carries two hidden fields:
//   _csrf  -- session-bound, the security control (same value all session)
//   _nonce -- fresh per render, the idempotency control (single use)
// The nonce costs nothing to mint and is only recorded server-side when a
// submission is actually accepted, so a page with ten forms writes nothing.
function csrfField(csrf) {
  return (
    `<input type="hidden" name="_csrf" value="${esc(csrf)}" />` +
    `<input type="hidden" name="_nonce" value="${crypto.randomUUID()}" />`
  );
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

// D1 stores datetimes as UTC "YYYY-MM-DD HH:MM:SS". The rest of the app prints
// them raw, which is fine for a log. It is not fine for a call queue: a founder
// in SAST reading "due 04:00" has to do timezone arithmetic before knowing
// whether to pick up the phone.
//
// So the queue leads with a relative duration instead. Relative durations are
// timezone-free, and "overdue by 2 days" is the thing being asked anyway. The
// absolute stamp stays available, explicitly labelled UTC, as the secondary.
function sqlUtcToMs(v) {
  if (!v) return NaN;
  const t = String(v).trim().replace(" ", "T");
  return Date.parse(/[Zz]|[+-]\d\d:?\d\d$/.test(t) ? t : t + "Z");
}

function humanGap(ms) {
  const mins = Math.round(Math.abs(ms) / 60000);
  if (mins < 60) return `${mins} min`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"}`;
  return `${Math.round(hours / 24)} days`;
}

// Returns null when there is no window, so callers can distinguish "not due for
// a while" from "never scheduled".
function callDue(dueAt, now = Date.now()) {
  const due = sqlUtcToMs(dueAt);
  if (!Number.isFinite(due)) return null;
  const diff = due - now;
  if (diff <= 0) return { due: true, text: diff > -60000 ? "Due now" : `Overdue by ${humanGap(diff)}`, cls: "red" };
  return { due: false, text: `Due in ${humanGap(diff)}`, cls: "" };
}

// pill kind: "green" | "red" | "" (muted/default)
function pill(label, kind = "", plain = false) {
  const cls = ["pill", kind ? `pill-${kind}` : "", plain ? "pill-plain" : ""].filter(Boolean).join(" ");
  return `<span class="${cls}">${esc(label)}</span>`;
}

const FOUNDER_NAV = [
  ["dashboard", "/dashboard", "Dashboard"],
  ["freelancers", "/freelancers", "Freelancers"],
  ["clients", "/clients", "Clients"],
  ["leads", "/leads", "Leads"],
  ["outreach", "/outreach", "Outreach"],
  ["calls", "/calls", "Calls"],
  ["revenue", "/revenue", "Revenue"],
  ["team", "/team", "Team"],
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

// The one piece of client script on the site, and it is a pure speed
// optimisation: it makes the light/dark switch instant instead of a page
// reload. The <a href="/theme/toggle"> underneath still works by itself, so
// with JS blocked the toggle degrades to the old server round-trip rather
// than breaking.
//
// A delegated listener rather than an inline onclick, so it hashes as an
// ordinary script block and doesn't lean on CSP's 'unsafe-hashes'. No fetch,
// so connect-src stays 'none'. Kept byte-for-byte stable because index.js
// pins its SHA-256 in the CSP -- edit this and the suite will tell you.
const THEME_SCRIPT = `<script>
document.addEventListener("click",function(e){
var a=e.target.closest("[data-theme-toggle]");
if(!a||e.metaKey||e.ctrlKey||e.shiftKey||e.button)return;
e.preventDefault();
var n=document.documentElement.dataset.theme==="light"?"dark":"light";
document.documentElement.dataset.theme=n;
document.querySelectorAll("[data-theme-toggle]").forEach(function(t){t.textContent=n==="dark"?"Dark":"Light"});
document.cookie="c7_theme="+n+"; Path=/; Max-Age=31536000; SameSite=Lax; Secure";
});
</script>`;

// The C7 mark, drawn as paths rather than <text> on purpose: a favicon that
// leans on a system font renders differently on every platform, and at 16px
// those differences are the whole image.
//
// Black tile with a red mark, per the brand's two-colour rule. It works in both
// tab strips for different reasons -- against a light one the black tile is the
// shape you see, against a dark one the tile disappears and the red mark floats.
//
// Geometry: the C is a 260-degree arc so the aperture stays open at small
// sizes (a tighter gap closes up and reads as an O), and the 7 is two strokes
// rather than a glyph. 4px strokes on a 32px grid keep both legible at 16.
export const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="7" fill="#0D0D0D"/>
  <path d="M14.86 11.40 A 6 6 0 1 0 14.86 20.60" fill="none" stroke="#C1272D" stroke-width="4" stroke-linecap="round"/>
  <path d="M18.6 11 H27 L21.4 21.6" fill="none" stroke="#C1272D" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

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

  const brand = `<div class="brandwrap"><span class="brand">Catalyst 7</span><span class="brand-sub">HQ</span></div>`;
  // The href is the no-JS path and still works on its own (server flips the
  // cookie and redirects back). The script below intercepts the click to make
  // the switch instant; if it never runs, nothing is lost but the speed.
  const modeToggle = `<a href="/theme/toggle" class="mode-toggle" data-theme-toggle>${themeLabel}</a>`;

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
<title>${esc(title)} &middot; Catalyst 7 HQ</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
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
/* Pills capitalize by default, which suits one-word statuses like "sent" but
   mangles a phrase into "Overdue By 30 Hours". */
.pill-plain{text-transform:none}

/* buttons */
.btn{font-size:13px;font-weight:600;padding:10px 16px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer;text-decoration:none;display:inline-block;font-family:inherit;line-height:1.2}
.btn-primary{border-color:var(--red);background:var(--red);color:var(--on-red)}
.btn-danger{border-color:var(--red-text);color:var(--red-text);background:transparent}
.btn-sm{font-size:12.5px;padding:7px 12px}
.btn[disabled]{opacity:.5;cursor:default}
.row-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.row-actions form{display:inline}
/* Visually hidden but still read out. The call-log selects sit in a dense table
   where a visible label per field would double the row height, but "Log the
   outcome..." as a placeholder is not a label a screen reader can rely on. */
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.call-log{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.call-log select,.call-log input[type=text]{margin:0}
.call-log-compact select{min-width:150px}
.call-log-compact input[type=text]{min-width:150px;flex:1 1 150px}
@media(max-width:860px){.call-log{flex-direction:column;align-items:stretch}}

/* forms */
form.plain{margin:0}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;padding:16px}
.field{display:flex;flex-direction:column;gap:6px}
.field.wide{grid-column:1/-1}
.field label{font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em}
input, select, textarea{font-size:13px;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--input-bg);color:var(--text);font-family:var(--font);width:100%}
textarea{min-height:70px;resize:vertical}
.form-foot{display:flex;justify-content:flex-end;gap:8px;padding:14px 16px;border-top:1px solid var(--border)}
/* Import form: fields sitting directly in a panel rather than inside a grid,
   so they carry their own padding. */
.field-block{padding:16px 16px 0}
/* The global rule stretches every input to 100%, which turns a checkbox into a
   block. Checkboxes opt out and sit inline with their label instead. */
.checkbox-field{padding:0 16px 4px}
.checkbox-field label{display:flex;align-items:center;gap:8px;text-transform:none;font-size:13px;font-weight:500;color:var(--text);letter-spacing:0}
.checkbox-field input[type=checkbox]{width:auto;margin:0;flex:0 0 auto}
.checkbox-field .hint{margin-top:6px}
/* Pasted data is data: monospace makes a shifted column visible. */
textarea.data-paste{font-family:var(--font-mono,ui-monospace,SFMono-Regular,Menlo,monospace);font-size:12px;min-height:220px;white-space:pre}

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

/* outreach timeline */
.timeline{list-style:none;margin:0;padding:0}
.timeline li{display:flex;gap:14px;padding:14px 16px;border-bottom:1px solid var(--border)}
.timeline li:last-child{border-bottom:none}
.tl-when{font-family:var(--font-mono);font-size:12px;color:var(--text-muted);white-space:nowrap;min-width:132px}
.tl-body{flex:1;min-width:0}
.tl-subject{font-size:13.5px;font-weight:600;word-break:break-word}
.tl-meta{font-size:12px;color:var(--text-muted);margin-top:3px}
.lead-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:var(--sp-5)}
.link-inline{color:var(--red-text);text-decoration:underline;font-weight:600}
.title-label{font-size:12px;color:var(--red-text);font-weight:600}
.title-edit{display:flex;gap:6px;margin-top:7px;max-width:290px}
.title-edit input{font-size:12px;padding:6px 8px}
.title-edit .btn{padding:6px 10px;font-size:12px;white-space:nowrap}
.code-big{font-family:var(--font-mono);font-size:19px;letter-spacing:.08em;font-weight:700;display:block;margin:10px 0;padding:14px;background:var(--input-bg);border:1px solid var(--red-text);border-radius:var(--radius);text-align:center;word-break:break-all}
</style>
</head>
<body>
${header}
<main${user ? "" : ' class="authmain"'}>
${body}
</main>
${THEME_SCRIPT}
</body>
</html>`;
}

// Google's mark, inlined as an SVG so the login page still makes zero
// external requests (and the CSP can keep default-src 'none').
const GOOGLE_MARK = `<svg class="gmark" viewBox="0 0 48 48" aria-hidden="true" focusable="false"><path fill="#4285F4" d="M45.1 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h11.8c-.5 2.7-2 5-4.4 6.6v5.5h7.1c4.1-3.8 6.6-9.4 6.6-16.1z"/><path fill="#34A853" d="M24 46c6 0 11-2 14.6-5.4l-7.1-5.5c-2 1.3-4.5 2.1-7.5 2.1-5.8 0-10.7-3.9-12.4-9.1H4.3v5.7C7.9 41 15.4 46 24 46z"/><path fill="#FBBC05" d="M11.6 28.1c-.4-1.3-.7-2.7-.7-4.1s.2-2.8.7-4.1v-5.7H4.3C2.8 17.1 2 20.4 2 24s.8 6.9 2.3 9.8l7.3-5.7z"/><path fill="#EA4335" d="M24 10.8c3.3 0 6.2 1.1 8.5 3.3l6.3-6.3C35 4.3 30 2 24 2 15.4 2 7.9 7 4.3 14.2l7.3 5.7c1.7-5.2 6.6-9.1 12.4-9.1z"/></svg>`;

// ---------- Auth pages ----------
export function loginPage({ error, theme, googleEnabled = false, next = null } = {}) {
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
        ${next ? `<input type="hidden" name="next" value="${esc(next)}" />` : ""}
        <div class="field"><label>Email</label><input type="email" name="email" required placeholder="you@catalyst7.co.za" /></div>
        <div class="field"><label>Password</label><input type="password" name="password" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" /></div>
        <button type="submit" class="btn btn-primary">Continue</button>
      </form>
      <div class="helper">Have an invite code? <a href="/register" class="link-inline">Create your account</a>.<br />Forgot your password? Ask a founder to send you a new invite link.</div>
    </div>`,
  });
}

// ---------- Public: self-service registration (invite code required) ----------
export function registerPage({ error, theme, name = "", email = "" } = {}) {
  return layout({
    title: "Create your account",
    theme,
    body: `
    <div class="authcard">
      <h1>Create your account</h1>
      <p class="lead">You'll need an invite code from one of the founders. The code decides what you can see once you're in.</p>
      ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
      <form class="plain" method="post" action="/register">
        <div class="field"><label>Invite code</label><input name="code" required autofocus placeholder="XXXXX-XXXXX-XXXXX" autocapitalize="characters" spellcheck="false" /></div>
        <div class="field"><label>Full name</label><input name="name" required value="${esc(name)}" placeholder="Somila Tenza Sogaxa" /></div>
        <div class="field"><label>Email</label><input type="email" name="email" required value="${esc(email)}" placeholder="you@catalyst7.co.za" /></div>
        <div class="field"><label>Password (min 8 characters)</label><input type="password" name="password" minlength="8" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" /></div>
        <div class="field"><label>Confirm password</label><input type="password" name="confirm" minlength="8" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" /></div>
        <button type="submit" class="btn btn-primary">Create account</button>
      </form>
      <div class="helper">Already have an account? <a href="/login" class="link-inline">Sign in</a>.</div>
    </div>`,
  });
}

export function totpVerifyPage({ error, theme, next = null } = {}) {
  return layout({
    title: "Verify it's you",
    theme,
    body: `
    <div class="authcard">
      <h1>Enter your code</h1>
      <p class="lead">Open your authenticator app and enter the 6-digit code to finish signing in.</p>
      ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
      <form class="plain" method="post" action="/login/2fa">
        ${next ? `<input type="hidden" name="next" value="${esc(next)}" />` : ""}
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
  mcpGrants = [],
  mcpUrl = "/mcp",
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
    <div class="panel"><div class="security-body">
      <h3 class="sub-label">Connected apps</h3>
      ${
        mcpGrants.length
          ? `<div class="security-copy">These applications act as you, within your role. They can read your data and add or qualify leads. They <strong>cannot approve outreach, send anything, or delete anything</strong>.</div>
             <div class="table-wrap"><table><thead><tr><th>Application</th><th>Connected</th><th>Last used</th><th class="right">Action</th></tr></thead><tbody>${mcpGrants
               .map(
                 (g) => `<tr>
                   <td class="strong">${esc(g.client_name || "Unnamed application")}</td>
                   <td class="mono muted nowrap">${esc(String(g.granted_at || "").slice(0, 16))}</td>
                   <td class="mono muted nowrap">${g.last_used_at ? esc(String(g.last_used_at).slice(0, 16)) : "never"}</td>
                   <td class="right"><form method="post" action="/security/connectors/revoke" class="row-actions">${csrfField(
                     csrf
                   )}<input type="hidden" name="client_id" value="${esc(g.client_id)}" /><button type="submit" class="btn btn-sm btn-danger">Disconnect</button></form></td>
                 </tr>`
               )
               .join("")}</tbody></table></div>`
          : `<div class="security-copy">No applications are connected to your account.<br /><br />
             To connect Claude, add a custom connector pointing at <span class="mono-box" style="display:inline-block;margin:6px 0 0">${esc(
               mcpUrl
             )}</span> and approve it when asked. It can read whatever your role can already see, and can add leads and record qualification on them. It <strong>cannot</strong> approve a lead for outreach or send anything &mdash; that stays with you, here in HQ.</div>`
      }
    </div></div>

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
            : `<div class="empty">No freelancers yet.<br/><label for="add-toggle" class="btn btn-primary" style="margin-top:12px">Add your first freelancer</label></div>`
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
            : `<div class="empty">No clients yet.<br/><label for="add-toggle" class="btn btn-primary" style="margin-top:12px">Add your first client</label></div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: Leads ----------
// Exported so index.js validates against the same list the UI renders and the
// database CHECK constraint enforces, rather than a third copy that can drift.
export const STAGES = ["new", "contacted", "qualified", "proposal", "won", "lost"];
export function leadsPage({ user, leads, csrf, theme, outreach = {} }) {
  const rows = leads
    .map((l) => {
      const opts = STAGES.map((s) => `<option value="${s}" ${s === l.stage ? "selected" : ""}>${s}</option>`).join("");
      const selCls = l.stage === "won" ? "stage-won" : l.stage === "lost" ? "stage-lost" : "";
      return `<tr>
      <td class="strong"><a href="/leads/${l.id}" class="link-inline" style="text-decoration:none">${esc(l.name)}</a>${
        // Scraped business leads have no separate contact person, so name and
        // company are the same string. Printing it twice just looks broken.
        l.company && l.company !== l.name ? `<br/><span class="hint">${esc(l.company)}</span>` : ""
      }</td>
      <td class="muted">${(() => {
        const o = outreach[l.id];
        if (!o) return "—";
        const bits = [];
        if (o.sent) bits.push(`${o.sent} sent`);
        if (o.replies) bits.push(`${o.replies} replied`);
        if (o.problems) bits.push(`${o.problems} failed`);
        return bits.length ? esc(bits.join(", ")) : "—";
      })()}</td>
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
      <div class="row-actions">
        <a href="/leads/import" class="btn">Import</a>
        <label for="add-toggle" class="btn btn-primary"><span class="toggle-open">Add lead</span><span class="toggle-close">Close</span></label>
      </div>
    </div>

    <div class="panel add-panel">
      <div class="panel-head">Add lead</div>
      <form class="plain" method="post" action="/leads">
        ${csrfField(csrf)}
        <div class="form-grid">
          <div class="field"><label>Name</label><input name="name" required placeholder="Zanele Buthelezi" /></div>
          <div class="field"><label>Company</label><input name="company" placeholder="Rivonia Retail Group" /></div>
          <div class="field"><label>Email</label><input name="contact_email" type="email" placeholder="zanele@rivonia.co.za" /></div>
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
            ? `<table><thead><tr><th>Lead</th><th>Outreach</th><th>Owner</th><th>Value</th><th class="right">Stage</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">No leads yet.<br/><label for="add-toggle" class="btn btn-primary" style="margin-top:12px">Add your first lead</label></div>`
        }
      </div>
    </div>
  `,
  });
}

// ---------- Founder: outreach approval queue ----------
// The decision point in the pipeline: Apify scrapes, a founder qualifies and
// approves here, then HQ triggers Make to send.
export function outreachQueuePage({ user, csrf, theme, queue, counts, recent, unmatched, sendingReady, webhookReady }) {
  const queueRows = queue
    .map(
      (l) => `<tr>
      <td class="strong"><a href="/leads/${l.id}" class="link-inline" style="text-decoration:none">${esc(l.name)}</a>${
        // Scraped business leads have no separate contact person, so name and
        // company are the same string. Printing it twice just looks broken.
        l.company && l.company !== l.name ? `<br/><span class="hint">${esc(l.company)}</span>` : ""
      }</td>
      <td class="muted">${l.contact_email ? esc(l.contact_email) : `<span class="hint">no email &mdash; can't be approved</span>`}</td>
      <td class="muted">${esc(l.source || "—")}</td>
      <td class="mono">${l.value_estimate ? money(l.value_estimate) : "—"}</td>
      <td class="right">
        <div class="row-actions">
          ${
            l.contact_email
              ? `<form method="post" action="/leads/${l.id}/outreach/approve">${csrfField(
                  csrf
                )}<input type="hidden" name="back" value="queue" /><button type="submit" class="btn btn-sm btn-primary">Approve</button></form>`
              : ""
          }
          <form method="post" action="/leads/${l.id}/outreach/reject">${csrfField(
            csrf
          )}<input type="hidden" name="back" value="queue" /><button type="submit" class="btn btn-sm">Reject</button></form>
        </div>
      </td>
    </tr>`
    )
    .join("");

  const activityRows = recent
    .map(
      (e) => `<tr>
      <td class="mono muted nowrap">${esc(String(e.occurred_at).replace("T", " ").slice(0, 16))}</td>
      <td class="strong">${
        e.lead_id ? `<a href="/leads/${e.lead_id}" class="link-inline" style="text-decoration:none">${esc(e.lead_name || e.lead_email)}</a>` : esc(e.lead_email || "—")
      }</td>
      <td>${
        e.kind === "reply" ? pill("reply", "green") : e.kind === "sent" ? pill("sent") : pill(e.kind, "red")
      }</td>
      <td class="detail">${esc(e.subject || e.detail || "—")}</td>
    </tr>`
    )
    .join("");

  return layout({
    user,
    active: "outreach",
    title: "Outreach",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Outreach</div>
      <div class="page-sub">Qualify and approve who gets emailed, then trigger the send. Nothing leaves HQ without an explicit approval.</div>
    </div>

    ${
      !sendingReady
        ? `<div class="msg msg-error">Sending isn't switched on yet. Set <strong>MAKE_OUTREACH_URL</strong> and <strong>MAKE_WEBHOOK_SECRET</strong> in the Worker's settings, then the Send button becomes active. You can still qualify and approve in the meantime.</div>`
        : ""
    }
    ${
      !webhookReady
        ? `<div class="msg msg-error">Inbound tracking isn't switched on &mdash; set <strong>MAKE_WEBHOOK_SECRET</strong> so Make can report what it sent.</div>`
        : ""
    }

    <div class="metrics-grid">
      <div class="metric-card"><div class="metric-label">Awaiting your decision</div><div class="metric-value">${counts.pending}</div></div>
      <div class="metric-card"><div class="metric-label">Approved to email</div><div class="metric-value">${counts.approved}</div></div>
      <div class="metric-card"><div class="metric-label">Rejected</div><div class="metric-value">${counts.rejected}</div></div>
    </div>

    <div class="panel">
      <div class="panel-head">Awaiting approval</div>
      <div class="table-wrap">
        ${
          queueRows
            ? `<table><thead><tr><th>Lead</th><th>Email</th><th>Source</th><th>Value</th><th class="right">Decision</th></tr></thead><tbody>${queueRows}</tbody></table>`
            : `<div class="empty">Nothing waiting. Scraped leads land here for you to qualify before anyone is emailed.</div>`
        }
      </div>
    </div>

    <h2 class="section-label" style="margin-top:32px">Recent email activity</h2>
    <div class="panel">
      <div class="table-wrap">
        ${
          activityRows
            ? `<table><thead><tr><th>When</th><th>Lead</th><th>What</th><th>Detail</th></tr></thead><tbody>${activityRows}</tbody></table>`
            : `<div class="empty">No outreach activity recorded yet.</div>`
        }
      </div>
    </div>

    ${
      unmatched.length
        ? `<h2 class="section-label" style="margin-top:32px">Sent to addresses not in the pipeline</h2>
           <div class="panel"><div class="table-wrap"><table><thead><tr><th>When</th><th>Address</th><th>What</th></tr></thead><tbody>${unmatched
             .map(
               (u) => `<tr><td class="mono muted nowrap">${esc(String(u.occurred_at).replace("T", " ").slice(0, 16))}</td>
               <td class="strong">${esc(u.lead_email || "—")}</td><td class="muted">${esc(u.kind)}</td></tr>`
             )
             .join("")}</tbody></table></div></div>
           <div class="hint" style="margin-top:8px">Usually a typo in the address, or a lead removed while a sequence was running.</div>`
        : ""
    }
  `,
  });
}

// ---------- Founder: single lead + outreach timeline ----------
// Step 1 of the CRM work: HQ shows what Make actually did, per lead.
// The Sequence B window on a single lead. Rendered only once a send has opened
// a window: before that there is nothing to say, and an empty "no call yet"
// block on every lead would be noise.
function callPanel(lead, csrf) {
  if (!lead.call_due_at) return "";

  if (lead.call_outcome) {
    const choice = CALL_OUTCOME_CHOICES.find(([v]) => v === lead.call_outcome);
    const label = choice ? choice[1] : lead.call_outcome;
    return `<div class="panel">
      <div class="panel-head">Call</div>
      <div class="security-body">
        <div class="security-status">${pill(label, lead.call_outcome === "skipped" ? "" : "green", true)}${
          lead.call_logged_by ? ` <span class="hint">logged by ${esc(lead.call_logged_by)}</span>` : ""
        }</div>
        ${
          lead.call_logged_at
            ? `<div class="hint" style="margin-top:10px">Logged ${esc(
                String(lead.call_logged_at).replace("T", " ").slice(0, 16)
              )} UTC. The call itself is on the timeline below.</div>`
            : ""
        }
        <div class="row-actions" style="justify-content:flex-start;margin-top:12px">
          <form method="post" action="/leads/${lead.id}/call/reopen">${csrfField(
            csrf
          )}<button type="submit" class="btn btn-sm">Logged by mistake &mdash; reopen</button></form>
        </div>
      </div>
    </div>`;
  }

  const state = callDue(lead.call_due_at);
  return `<div class="panel">
    <div class="panel-head">Call</div>
    <div class="security-body">
      <div class="security-status">${state ? pill(state.text, state.cls, true) : ""}${
        lead.call_due_at
          ? ` <span class="hint mono">${esc(String(lead.call_due_at).replace("T", " ").slice(0, 16))} UTC</span>`
          : ""
      }</div>
      <div class="security-copy" style="margin-top:10px">
        Sequence B calls this lead once the window closes, whether or not they replied.
        ${state && !state.due ? "You can still call early &mdash; logging is open now." : ""}
      </div>
      <div style="margin-top:14px">${callLogForm(lead, csrf)}</div>
    </div>
  </div>`;
}

export function leadDetailPage({ user, lead, events, theme, webhookReady, csrf, sendingReady = false }) {
  const kindPill = (k) =>
    k === "reply"
      ? pill("reply", "green")
      : k === "sent"
        ? pill("sent")
        : k === "call"
          ? pill("call", "green")
          : pill(k, "red");

  const rows = events.length
    ? `<ul class="timeline">${events
        .map(
          (e) => `<li>
            <span class="tl-when">${esc(String(e.occurred_at).replace("T", " ").slice(0, 16))}</span>
            <span class="tl-body">
              <span class="tl-subject">${esc(e.subject || (e.kind === "reply" ? "Replied" : e.kind === "sent" ? "Email sent" : "Delivery problem"))}</span>
              <div class="tl-meta">
                ${kindPill(e.kind)}
                ${e.sequence ? ` &middot; ${esc(e.sequence)}` : ""}${e.step ? ` step ${esc(e.step)}` : ""}
                ${e.detail ? `<br/>${esc(e.detail)}` : ""}
              </div>
            </span>
          </li>`
        )
        .join("")}</ul>`
    : `<div class="empty">${
        webhookReady
          ? "No outreach recorded for this lead yet. Events appear here as your Make scenario reports them."
          : "Outreach tracking isn't switched on yet &mdash; see Settings for the webhook setup."
      }</div>`;

  const sent = events.filter((e) => e.kind === "sent").length;
  const replies = events.filter((e) => e.kind === "reply").length;
  const problems = events.filter((e) => e.kind === "bounce" || e.kind === "failed").length;

  return layout({
    user,
    active: "leads",
    title: esc(lead.name),
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">${esc(lead.name)}</div>
      <div class="page-sub">
        ${lead.company && lead.company !== lead.name ? esc(lead.company) + " &middot; " : ""}${esc(lead.stage)}
        ${lead.owner ? ` &middot; owner ${esc(lead.owner)}` : ""}
        ${lead.contact_email ? ` &middot; ${esc(lead.contact_email)}` : " &middot; no email on file"}
      </div>
    </div>

    <div class="lead-grid">
      <div class="metric-card"><div class="metric-label">Emails sent</div><div class="metric-value">${sent}</div></div>
      <div class="metric-card"><div class="metric-label">Replies</div><div class="metric-value">${replies}</div></div>
      <div class="metric-card"><div class="metric-label">Delivery problems</div><div class="metric-value">${problems}</div></div>
      <div class="metric-card"><div class="metric-label">Value estimate</div><div class="metric-value">${
        lead.value_estimate ? money(lead.value_estimate) : "&mdash;"
      }</div></div>
    </div>

    <div class="panel">
      <div class="panel-head">Outreach</div>
      <div class="security-body">
        <div class="security-status">${
          lead.outreach_status === "approved"
            ? pill("approved to email", "green", true)
            : lead.outreach_status === "rejected"
              ? pill("rejected", "red")
              : pill("awaiting your decision", "", true)
        }${lead.outreach_approved_by ? ` <span class="hint">by ${esc(lead.outreach_approved_by)}</span>` : ""}</div>
        <div class="row-actions" style="justify-content:flex-start;gap:10px;margin-top:12px">
          ${
            lead.outreach_status !== "approved" && lead.contact_email
              ? `<form method="post" action="/leads/${lead.id}/outreach/approve">${csrfField(csrf)}<button type="submit" class="btn btn-primary">Approve for outreach</button></form>`
              : ""
          }
          ${
            lead.outreach_status !== "rejected"
              ? `<form method="post" action="/leads/${lead.id}/outreach/reject">${csrfField(csrf)}<button type="submit" class="btn">Reject</button></form>`
              : ""
          }
          ${
            lead.outreach_status === "approved" && lead.contact_email && sendingReady
              ? `<form method="post" action="/leads/${lead.id}/outreach/send" onsubmit="return confirm('Send the outreach email to this lead now?');">${csrfField(
                  csrf
                )}<button type="submit" class="btn btn-primary">Send outreach email</button></form>`
              : ""
          }
        </div>
        ${
          !lead.contact_email
            ? `<div class="hint" style="margin-top:10px">No email address on this lead, so it can't be approved or sent to.</div>`
            : lead.outreach_status === "approved" && !sendingReady
              ? `<div class="hint" style="margin-top:10px">Approved, but sending isn't configured yet &mdash; see the Outreach page.</div>`
              : ""
        }
        ${
          lead.outreach_last_sent_at
            ? `<div class="hint" style="margin-top:10px">Last sent ${esc(String(lead.outreach_last_sent_at).replace("T", " ").slice(0, 16))}.</div>`
            : ""
        }
      </div>
    </div>

    ${callPanel(lead, csrf)}

    <div class="panel">
      <div class="panel-head">Outreach activity</div>
      ${rows}
    </div>

    ${lead.notes ? `<div class="panel"><div class="panel-head">Notes</div><div class="security-body"><div class="security-copy">${esc(lead.notes)}</div></div></div>` : ""}

    <p><a href="/leads" class="btn btn-sm">Back to leads</a></p>
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
            : `<div class="empty">No revenue logged yet.<br/><label for="add-toggle" class="btn btn-primary" style="margin-top:12px">Log your first entry</label></div>`
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

// ---------- MCP connector: consent + info ----------
// The consent screen is the whole point of choosing OAuth over a shared API
// key: the token gets bound to whoever is signed in here, so the audit log
// keeps naming a person.
export function consentPage({ user, theme, csrf, clientName, scope, query }) {
  const who = esc(clientName || "An application");
  return layout({
    user,
    title: "Authorise access",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">${who} wants access to your Catalyst 7 HQ data</div>
      <div class="page-sub">You're signed in as ${esc(user.name)}${user.title ? ` &middot; ${esc(user.title)}` : ""} &middot; ${esc(user.email)}</div>
    </div>

    <div class="panel"><div class="security-body">
      <div class="security-status">${pill(esc(scope), "green")}</div>
      <div class="security-copy">
        It will be able to <strong>read</strong>, as you:
        <ul style="margin:10px 0 0 18px;line-height:1.8">
          ${
            user.role === "founder"
              ? `<li>This week's numbers &mdash; hours, revenue, pipeline, log compliance</li>
                 <li>Your leads, clients, revenue entries and freelancer roster</li>`
              : `<li>Your own weekly log and history</li>`
          }
        </ul>
        ${
          user.role === "founder"
            ? `<br />
        It will also be able to <strong>write</strong>, as you:
        <ul style="margin:10px 0 0 18px;line-height:1.8">
          <li>Add leads to your pipeline &mdash; typically ones it has just researched</li>
          <li>Record qualification on a lead: move its stage, set a value, add notes</li>
        </ul>`
            : ""
        }
        <br />
        It <strong>cannot approve outreach or send anything.</strong> ${
          user.role === "founder"
            ? "Leads it adds always arrive awaiting your approval, and approving is only ever done by you, here in HQ. "
            : ""
        }It cannot delete anything, and it cannot see passwords, 2FA secrets, or the audit log. Access follows
        your role, so it can never reach more than you can.
        <br /><br />
        Every change it makes is recorded in the audit log as a connector action, so you can tell it apart
        from something a person did. You can withdraw this at any time from <strong>Security</strong> in the nav.
      </div>
      <div class="row-actions" style="justify-content:flex-start;gap:10px">
        <form method="post" action="/oauth/authorize${esc(query)}">
          ${csrfField(csrf)}
          <input type="hidden" name="decision" value="allow" />
          <button type="submit" class="btn btn-primary">Allow access</button>
        </form>
        <form method="post" action="/oauth/authorize${esc(query)}">
          ${csrfField(csrf)}
          <input type="hidden" name="decision" value="deny" />
          <button type="submit" class="btn">Cancel</button>
        </form>
      </div>
    </div></div>

    <div class="hint" style="margin-top:14px">
      If you didn't just try to connect something, press Cancel &mdash; this page only appears when an
      application asked for access.
    </div>
  `,
  });
}

export function mcpAboutPage({ theme, origin }) {
  return layout({
    title: "Connector",
    theme,
    body: `
    <div class="authcard" style="max-width:640px">
      <h1>Catalyst 7 HQ connector</h1>
      <p class="lead">The studio's numbers and pipeline, for use as a Claude connector. Reads anything your role can see; adds and qualifies leads; never approves or sends.</p>
      <div class="security-copy">
        Add it in Claude under <strong>Settings &rarr; Connectors &rarr; Add custom connector</strong>, using:
        <span class="mono-box">${esc(origin)}/mcp</span>
        You'll be asked to sign in to HQ and approve access. The connector acts as you and follows your
        role &mdash; a freelancer's connector only ever sees their own weekly log.
        <br /><br />
        It can read your data, add leads to the pipeline, and record what it found out about them. It
        <strong>cannot approve a lead for outreach or send anything</strong>: that decision stays with a
        founder, in HQ. Leads it adds always arrive awaiting your approval. Every write is recorded in the
        audit log as a connector action, so you can tell it apart from something a person did.
        <br /><br />
        Revoke it any time from Security.
      </div>
    </div>`,
  });
}

// ---------- Founder: Team / user accounts ----------
export function teamPage({
  user,
  users,
  unlinkedFreelancers = [],
  inviteCodes = [],
  registerUrl = "/register",
  csrf,
  theme,
  error,
  message,
  inviteLink,
  inviteFor,
  newCode,
}) {
  const statusPill = (u) => {
    if (u.has_password) return pill("active", "green");
    if (u.invite_pending) return pill("invite sent");
    return pill("no access", "red");
  };

  const rows = users
    .map((u) => {
      const isSelf = u.id === user.id;
      return `<tr>
      <td class="strong">${esc(u.name)}${isSelf ? ' <span class="hint">(you)</span>' : ""}
        ${u.title ? `<br/><span class="title-label">${esc(u.title)}</span>` : ""}
        ${u.freelancer_name ? `<br/><span class="hint">profile: ${esc(u.freelancer_name)}</span>` : ""}
        <form method="post" action="/team/${u.id}/title" class="title-edit">
          ${csrfField(csrf)}
          <input name="title" value="${esc(u.title || "")}" placeholder="Add a job title" maxlength="60" />
          <button type="submit" class="btn btn-sm">Save</button>
        </form>
      </td>
      <td class="muted">${esc(u.email)}</td>
      <td>${u.role === "founder" ? pill("founder", "green") : pill("freelancer")}</td>
      <td>${statusPill(u)}</td>
      <td class="muted nowrap">${u.totp_enabled ? "2FA on" : "&mdash;"}${u.google_linked ? " &middot; Google" : ""}</td>
      <td class="right">
        <div class="row-actions">
          <form method="post" action="/team/${u.id}/invite">${csrfField(csrf)}<button type="submit" class="btn btn-sm">${
            u.has_password ? "Reset access" : "New link"
          }</button></form>
          ${
            isSelf
              ? ""
              : `<form method="post" action="/team/${u.id}/revoke" onsubmit="return confirm('Revoke access for this person? They will be signed out everywhere and will need a new invite link to get back in.');">${csrfField(
                  csrf
                )}<button type="submit" class="btn btn-sm btn-danger">Revoke</button></form>`
          }
        </div>
      </td>
    </tr>`;
    })
    .join("");

  const freelancerOptions = unlinkedFreelancers.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");

  return layout({
    user,
    active: "team",
    title: "Team",
    theme,
    body: `
    <input type="checkbox" id="add-toggle" class="form-toggle" />
    <div class="page-head-row">
      <div>
        <div class="page-title">Team</div>
        <div class="page-sub">${users.length} ${users.length === 1 ? "account" : "accounts"} &middot; who can sign in, and what they can see</div>
      </div>
      <label for="add-toggle" class="btn btn-primary"><span class="toggle-open">Add person</span><span class="toggle-close">Close</span></label>
    </div>

    ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}
    ${message ? `<div class="msg msg-ok">${esc(message)}</div>` : ""}
    ${
      inviteLink
        ? `<div class="msg msg-ok">Invite link${inviteFor ? ` for ${esc(inviteFor)}` : ""} &mdash; send it via WhatsApp or email, it works once and then expires:<span class="mono-box">${esc(
            inviteLink
          )}</span><span class="hint">This is the only time it's shown. If it gets lost, use "New link" to issue another.</span></div>`
        : ""
    }

    <div class="panel add-panel">
      <div class="panel-head">Add someone to the team</div>
      <form class="plain" method="post" action="/team">
        ${csrfField(csrf)}
        <div class="form-grid">
          <div class="field"><label>Full name</label><input name="name" required placeholder="Somila" /></div>
          <div class="field"><label>Email</label><input name="email" type="email" required placeholder="somila@catalyst7.co.za" /></div>
          <div class="field"><label>Job title (optional)</label><input name="title" maxlength="60" placeholder="CEO / Co-Founder" /></div>
          <div class="field"><label>Role &mdash; what they can access</label>
            <select name="role">
              <option value="founder">Founder &mdash; full access</option>
              <option value="freelancer">Freelancer &mdash; own weekly log only</option>
            </select>
          </div>
          <div class="field"><label>Freelancer profile (freelancers only)</label>
            <select name="freelancer_id">
              <option value="">&mdash;</option>
              ${freelancerOptions}
            </select>
            <span class="hint">${
              unlinkedFreelancers.length
                ? "Required if the role is Freelancer, so their weekly log points at the right person."
                : "No unlinked freelancer profiles. Add one on the Freelancers page first."
            }</span>
          </div>
        </div>
        <div class="form-foot">
          <label for="add-toggle" class="btn">Cancel</label>
          <button type="submit" class="btn btn-primary">Add person</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Sign-in</th><th class="right">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">No accounts yet.</div>`
        }
      </div>
    </div>

    <h2 class="section-label" style="margin-top:32px">Invite codes</h2>
    <div class="panel">
      <div class="security-body">
        <div class="security-copy" style="margin-bottom:16px">
          An invite code lets someone create their own account at <span class="mono-box" style="display:inline-block;margin:0">${esc(
            registerUrl
          )}</span> — they choose their own name, email and password. <strong>The code decides their role, not them.</strong> Each code works once and expires.
        </div>
        ${
          newCode
            ? `<div class="msg msg-ok codes-warn"><strong>Send this to them now — it isn't shown again.</strong><span class="code-big">${esc(
                newCode
              )}</span>Along with the link: ${esc(registerUrl)}</div>`
            : ""
        }
        <form method="post" action="/team/codes">
          ${csrfField(csrf)}
          <div class="form-grid" style="padding:0 0 14px">
            <div class="field"><label>Role this code creates</label>
              <select name="role">
                <option value="founder">Founder &mdash; full access</option>
                <option value="freelancer">Freelancer &mdash; own weekly log only</option>
              </select>
            </div>
            <div class="field"><label>Freelancer profile (freelancer codes only)</label>
              <select name="freelancer_id">
                <option value="">&mdash;</option>
                ${unlinkedFreelancers.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("")}
              </select>
            </div>
            <div class="field"><label>Expires after</label>
              <select name="expires_days">
                <option value="1">1 day</option>
                <option value="7" selected>7 days</option>
                <option value="14">14 days</option>
                <option value="30">30 days</option>
              </select>
            </div>
            <div class="field"><label>Job title for the account</label><input name="title" maxlength="60" placeholder="CEO / Co-Founder" /></div>
            <div class="field"><label>Note (who it's for)</label><input name="note" placeholder="Somila" /></div>
          </div>
          <button type="submit" class="btn btn-primary">Generate invite code</button>
        </form>
      </div>
      <div class="table-wrap">
        ${
          inviteCodes.length
            ? `<table><thead><tr><th>For</th><th>Role</th><th>Status</th><th>Expires</th><th class="right">Action</th></tr></thead><tbody>${inviteCodes
                .map((c) => {
                  const status = c.used_at
                    ? pill(`used by ${c.used_by_name || "someone"}`, "green")
                    : c.expired
                      ? pill("expired", "red")
                      : pill("open");
                  return `<tr>
                    <td class="strong">${esc(c.note || "—")}${c.freelancer_name ? `<br/><span class="hint">${esc(c.freelancer_name)}</span>` : ""}</td>
                    <td class="muted" style="text-transform:capitalize">${esc(c.role)}</td>
                    <td>${status}</td>
                    <td class="mono muted nowrap">${esc(String(c.expires_at).slice(0, 10))}</td>
                    <td class="right">${
                      c.used_at || c.expired
                        ? ""
                        : `<form method="post" action="/team/codes/${c.id}/revoke" class="row-actions">${csrfField(
                            csrf
                          )}<button type="submit" class="btn btn-sm btn-danger">Cancel</button></form>`
                    }</td>
                  </tr>`;
                })
                .join("")}</tbody></table>`
            : `<div class="empty">No invite codes yet.</div>`
        }
      </div>
    </div>

    <h2 class="section-label" style="margin-top:32px">What the roles mean</h2>
    <div class="panel"><div class="security-body">
      <div class="security-copy" style="max-width:640px">
        <strong>Founder</strong> sees everything &mdash; dashboard, revenue, clients, leads, the audit log, and this page.<br/><br/>
        <strong>Freelancer</strong> only ever sees their own weekly log and history. They cannot reach any founder page, and cannot see another freelancer's hours.<br/><br/>
        Nobody can change their own role, and roles are checked on the server for every request &mdash; not just hidden in the menu.
      </div>
    </div></div>
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
      <td class="mono muted nowrap">${esc(r.ip_address || "—")}</td>
      <td class="nowrap">${r.status && r.status !== "success" ? pill(r.status, "red") : pill("ok", "green")}</td>
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
      <div class="page-sub">Who changed what, when, from where, and whether it worked. Last 100 actions.</div>
    </div>
    <div class="panel">
      <div class="table-wrap">
        ${
          trs
            ? `<table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Entity</th><th>Detail</th><th>From</th><th>Result</th></tr></thead><tbody>${trs}</tbody></table>`
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

// The C7 standard asks for an explicit Unauthorized state. The HTTP status
// stays 404 on purpose -- a 403 would confirm the page exists, which tells an
// account more than it should learn about what it cannot reach. The *page*
// explains; the status code stays quiet.
export function restrictedPage({ user, theme }) {
  const home = user && user.role === "freelancer" ? "/log" : "/dashboard";
  return layout({
    user,
    title: "Not available",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">That page isn't part of your access</div>
      <div class="page-sub">You're signed in as ${esc(user.name)}${user.title ? ` &middot; ${esc(user.title)}` : ""}.</div>
    </div>
    <div class="panel"><div class="security-body">
      <div class="security-status">${pill(user.role === "freelancer" ? "freelancer access" : "founder access", "")}</div>
      <div class="security-copy">
        ${
          user.role === "freelancer"
            ? "Your account covers your own weekly log and history. Dashboard, revenue, clients, leads and team management are founder-only — that's by design, not a fault."
            : "This page either doesn't exist or isn't available to your account."
        }
      </div>
      <a href="${home}" class="btn btn-primary">${user.role === "freelancer" ? "Go to this week's log" : "Back to the dashboard"}</a>
    </div></div>
    <div class="hint" style="margin-top:14px">If you think you should have access to this, ask a founder — they can change it on the Team page.</div>
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

// ---------- Founder: the Sequence B call queue (CRM step 3) ----------
//
// Sequence B sends, waits a short window, then calls REGARDLESS of whether the
// lead replied. This page is that window made visible. It is the step the
// Call-Timing Decision Log records as having "no tool, human, off the tracker".
//
// Two things it deliberately does NOT do:
//   - It does not hide leads that already replied. Calling everyone is what
//     makes the three outcomes comparable; filtering repliers out would bias
//     the data toward the least engaged half of the batch.
//   - It does not refuse an early call. A window that is still open shows as
//     waiting, but the log form is live the whole time.
const CALL_OUTCOME_CHOICES = [
  ["picked_up_cold", "Picked up cold", "Answered the call, no email reply beforehand"],
  ["replied_first", "Replied first", "Had already replied to the email"],
  ["no_response", "No response", "No reply, and the call went unanswered"],
  ["skipped", "Skipped", "Deliberately not called (kept out of the comparison)"],
];

function callLogForm(lead, csrf, { compact = false, back = "" } = {}) {
  const options = CALL_OUTCOME_CHOICES.map(
    ([value, label]) => `<option value="${value}">${esc(label)}</option>`
  ).join("");
  return `<form method="post" action="/leads/${lead.id}/call/log" class="call-log${compact ? " call-log-compact" : ""}">
    ${csrfField(csrf)}
    ${back ? `<input type="hidden" name="back" value="${esc(back)}" />` : ""}
    <label class="sr-only" for="outcome-${lead.id}">Call outcome</label>
    <select id="outcome-${lead.id}" name="outcome" required>
      <option value="">Log the outcome&hellip;</option>
      ${options}
    </select>
    <label class="sr-only" for="notes-${lead.id}">Call notes</label>
    <input id="notes-${lead.id}" type="text" name="notes" maxlength="1000" placeholder="What was said (optional)" />
    <button type="submit" class="btn btn-sm btn-primary">Log call</button>
  </form>`;
}

export function callQueuePage({ user, csrf, theme, queue, counts, stats, windowHours }) {
  const rows = queue
    .map((l) => {
      const state = callDue(l.call_due_at);
      return `<tr>
      <td class="strong"><a href="/leads/${l.id}" class="link-inline" style="text-decoration:none">${esc(l.name)}</a>${
        // Scraped business leads have no separate contact person, so name and
        // company are the same string. Printing it twice just looks broken.
        l.company && l.company !== l.name ? `<br/><span class="hint">${esc(l.company)}</span>` : ""
      }</td>
      <td>${state ? pill(state.text, state.cls, true) : pill("no window")}${
        l.call_due_at
          ? `<br/><span class="hint mono">${esc(String(l.call_due_at).replace("T", " ").slice(0, 16))} UTC</span>`
          : ""
      }</td>
      <td>${
        l.replied_since_send
          ? `${pill("replied", "green")}<br/><span class="hint">call anyway</span>`
          : `<span class="hint">no reply yet</span>`
      }</td>
      <td class="muted">${l.contact_email ? esc(l.contact_email) : "&mdash;"}</td>
      <td>${callLogForm(l, csrf, { compact: true, back: "calls" })}</td>
    </tr>`;
    })
    .join("");

  const statRow = [
    ["picked_up_cold", "Picked up cold"],
    ["replied_first", "Replied first"],
    ["no_response", "No response"],
  ]
    .map(
      ([k, label]) =>
        `<div class="metric-card"><div class="metric-label">${label}</div><div class="metric-value">${stats[k]}</div></div>`
    )
    .join("");

  return layout({
    user,
    active: "calls",
    title: "Calls",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Calls</div>
      <div class="page-sub">
        Sequence B: send, wait ${windowHours} hours, then call &mdash; whether or not they replied. Log every outcome.
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card"><div class="metric-label">Due now</div><div class="metric-value">${counts.due}</div></div>
      <div class="metric-card"><div class="metric-label">Window still open</div><div class="metric-value">${counts.waiting}</div></div>
      <div class="metric-card"><div class="metric-label">Calls logged</div><div class="metric-value">${stats.comparable + stats.skipped}</div></div>
    </div>

    <div class="panel">
      <div class="panel-head">The queue</div>
      <div class="table-wrap">
        ${
          rows
            ? `<table><thead><tr><th>Lead</th><th>Window</th><th>Replied?</th><th>Email</th><th>Outcome</th></tr></thead><tbody>${rows}</tbody></table>`
            : `<div class="empty">Nothing waiting on a call. A lead joins this queue the moment an outreach email sends successfully.</div>`
        }
      </div>
    </div>

    <h2 class="section-label" style="margin-top:32px">Outcomes so far</h2>
    <div class="metrics-grid">${statRow}</div>
    <div class="hint" style="margin-top:8px">
      ${stats.comparable} comparable ${stats.comparable === 1 ? "call" : "calls"}${
        stats.skipped ? `, plus ${stats.skipped} skipped and excluded` : ""
      }. Because every lead is called regardless of response, these three buckets are directly comparable across a batch.
    </div>

    <p style="margin-top:24px"><a href="/outreach" class="btn btn-sm">Back to outreach</a></p>
  `,
  });
}

// ---------- Founder: import scraped leads ----------
//
// Step 1 of the pipeline the Call-Timing Decision Log describes: Apify scrapes,
// a founder qualifies in HQ, approves, then outreach goes. Until this existed
// the scrape landed nowhere and leads had to be retyped one at a time.
//
// Two-step on purpose. A paste is opaque -- you cannot tell by looking whether
// a column shifted or an email column is full of "N/A" -- so nothing is written
// until the parse has been shown back and confirmed.
export function leadImportPage({ user, csrf, theme, error = null, raw = "", source = "apify", skipNoEmail = true }) {
  return layout({
    user,
    active: "leads",
    title: "Import leads",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Import leads</div>
      <div class="page-sub">Paste an Apify export. Nothing is saved until you have seen what it parsed.</div>
    </div>

    ${error ? `<div class="msg msg-error">${esc(error)}</div>` : ""}

    <div class="panel">
      <div class="panel-head">Paste the export</div>
      <form class="plain" method="post" action="/leads/import">
        ${csrfField(csrf)}
        <div class="field field-block">
          <label for="raw">JSON or CSV</label>
          <textarea id="raw" name="raw" rows="12" required class="data-paste"
            placeholder='Paste the Apify dataset export here.

JSON:  [{"title":"Braamfontein Bakery","address":"12 Smit St","phone":"011 555 0100","website":"","emails":["thandi@bakery.co.za"]}]

CSV:   title,address,phone,website,email
       Braamfontein Bakery,12 Smit St,011 555 0100,,thandi@bakery.co.za'>${esc(raw)}</textarea>
        </div>
        <div class="form-grid">
          <div class="field"><label>Source label</label><input name="source" value="${esc(source)}" placeholder="apify" /></div>
        </div>
        <div class="field checkbox-field">
          <label><input type="checkbox" name="skip_no_email" value="1" ${skipNoEmail ? "checked" : ""} />
          Skip rows with no email address</label>
          <div class="hint">They can't be emailed, and they can't be reliably de-duplicated on a re-import.</div>
        </div>
        <div class="form-foot">
          <a href="/leads" class="btn">Cancel</a>
          <button type="submit" class="btn btn-primary">Preview</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <div class="panel-head">What it reads</div>
      <div class="security-body">
        <div class="security-copy">
          Business name comes from <span class="mono">title</span>, <span class="mono">name</span> or
          <span class="mono">companyName</span>; email from <span class="mono">email</span>,
          <span class="mono">emails</span> or <span class="mono">contact_email</span>. Field names are matched
          loosely, so <span class="mono">contactEmail</span> and <span class="mono">Contact Email</span> both work.
        </div>
        <div class="security-copy" style="margin-top:10px">
          Phone, address, category, rating and website are kept as notes on the lead &mdash; including
          <strong>&ldquo;No website found&rdquo;</strong>, since for these clusters the absence is the qualifying signal.
        </div>
      </div>
    </div>
  `,
  });
}

const IMPORT_STATUS = {
  new: ["will import", "green"],
  duplicate: ["already in HQ", ""],
  no_email: ["no email — skipped", ""],
  invalid: ["no name — can't import", "red"],
};

export function leadImportPreviewPage({ user, csrf, theme, rows, counts, raw, source, skipNoEmail }) {
  const shown = rows.slice(0, 200);
  const body = shown
    .map((r) => {
      const [label, kind] = IMPORT_STATUS[r.status] || [r.status, ""];
      return `<tr>
      <td class="strong">${esc(r.name || "—")}${
        r.company && r.company !== r.name ? `<br/><span class="hint">${esc(r.company)}</span>` : ""
      }</td>
      <td class="muted">${
        r.contact_email
          ? esc(r.contact_email)
          : r.rejected_email
            ? `<span class="hint">ignored: ${esc(r.rejected_email)}</span>`
            : `<span class="hint">—</span>`
      }</td>
      <td class="detail">${r.notes ? esc(r.notes) : "—"}</td>
      <td>${pill(label, kind, true)}</td>
    </tr>`;
    })
    .join("");

  return layout({
    user,
    active: "leads",
    title: "Import preview",
    theme,
    body: `
    <div class="page-head">
      <div class="page-title">Import preview</div>
      <div class="page-sub">Nothing has been saved yet. Check this reads the way you expect, then confirm.</div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card"><div class="metric-label">Will import</div><div class="metric-value">${counts.new || 0}</div></div>
      <div class="metric-card"><div class="metric-label">Already in HQ</div><div class="metric-value">${counts.duplicate || 0}</div></div>
      <div class="metric-card"><div class="metric-label">No email</div><div class="metric-value">${counts.no_email || 0}</div></div>
      <div class="metric-card"><div class="metric-label">Unusable</div><div class="metric-value">${counts.invalid || 0}</div></div>
    </div>

    ${
      counts.new
        ? ""
        : `<div class="msg msg-error">Nothing here would be imported. If that's a surprise, the columns may not have lined up &mdash; go back and check the paste.</div>`
    }

    <div class="panel">
      <div class="panel-head">Parsed rows${rows.length > shown.length ? ` &mdash; showing the first ${shown.length} of ${rows.length}` : ""}</div>
      <div class="table-wrap">
        <table><thead><tr><th>Lead</th><th>Email</th><th>Notes</th><th>Outcome</th></tr></thead><tbody>${body}</tbody></table>
      </div>
    </div>

    <form method="post" action="/leads/import/confirm" class="plain" style="margin-top:20px">
      ${csrfField(csrf)}
      <input type="hidden" name="raw" value="${esc(raw)}" />
      <input type="hidden" name="source" value="${esc(source)}" />
      ${skipNoEmail ? `<input type="hidden" name="skip_no_email" value="1" />` : ""}
      <div class="form-foot">
        <a href="/leads/import" class="btn">Back</a>
        <button type="submit" class="btn btn-primary" ${counts.new ? "" : "disabled"}>
          Import ${counts.new || 0} ${counts.new === 1 ? "lead" : "leads"}
        </button>
      </div>
    </form>
  `,
  });
}
