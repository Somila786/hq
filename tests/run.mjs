// End-to-end integration tests for Catalyst 7 KPI.
//
// These drive the real Worker (`src/index.js`) with real Request objects
// against a real SQLite engine (`node:sqlite`, wrapped to look like D1 --
// see tests/d1.mjs). Nothing here is mocked or reimplemented.
//
// No test framework: `node tests/run.mjs`.
// On Node 20/22 add --experimental-sqlite; on Node 23+ node:sqlite is on by
// default and the flag is unnecessary.

import worker from "../src/index.js";
import { setPassword, totpCodeNow, generateTotpSecret } from "../src/auth.js";
import * as db from "../src/db.js";
import { makeEnv } from "./d1.mjs";

const ORIGIN = "https://kpi.catalyst7.test";

// ---------------------------------------------------------------- harness --

let passed = 0;
const failures = [];
let current = "";

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}
function eq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || "values differ"}\n    expected: ${JSON.stringify(expected)}\n    actual:   ${JSON.stringify(actual)}`);
  }
}
function has(haystack, needle, msg) {
  if (!String(haystack).includes(needle)) {
    throw new Error(`${msg || "missing substring"}: ${JSON.stringify(needle)}`);
  }
}
function lacks(haystack, needle, msg) {
  if (String(haystack).includes(needle)) {
    throw new Error(`${msg || "unexpected substring"}: ${JSON.stringify(needle)}`);
  }
}

async function test(name, fn) {
  current = name;
  try {
    await fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures.push({ name, err });
    console.log(`  FAIL ${name}\n       ${String(err.message).split("\n").join("\n       ")}`);
  }
}

// ------------------------------------------------------------ request kit --

function req(path, { method = "GET", cookies = {}, form = null, headers = {} } = {}) {
  const h = new Headers(headers);
  const cookieStr = Object.entries(cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  if (cookieStr) h.set("Cookie", cookieStr);
  const init = { method, headers: h };
  if (form) init.body = new URLSearchParams(form);
  return new Request(ORIGIN + path, init);
}

function setCookie(res, name) {
  for (const raw of res.headers.getSetCookie()) {
    const [pair] = raw.split(";");
    const idx = pair.indexOf("=");
    if (pair.slice(0, idx).trim() === name) return pair.slice(idx + 1).trim();
  }
  return null;
}

function rawSetCookie(res, name) {
  return res.headers.getSetCookie().find((c) => c.startsWith(name + "=")) || null;
}

// ---------------------------------------------------------------- seeding --

const FOUNDER_PW = "correct-horse-battery";
const FREELANCER_PW = "another-good-passphrase";

async function seedFounder(env, email = "thembalethu@catalyst7.co.za") {
  await env.DB.prepare("INSERT INTO users (email, name, role) VALUES (?, 'Thembalethu', 'founder')").bind(email).run();
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  await setPassword(env, u.id, FOUNDER_PW);
  return { id: u.id, email };
}

async function seedFreelancer(env, email = "naledi@example.com") {
  await env.DB.prepare("INSERT INTO freelancers (name, email, role_title, rate_type, rate_amount) VALUES ('Naledi Khumalo', ?, 'Designer', 'hourly', 650)")
    .bind(email)
    .run();
  const f = await env.DB.prepare("SELECT * FROM freelancers WHERE email = ?").bind(email).first();
  await env.DB.prepare("INSERT INTO users (email, name, role, freelancer_id) VALUES (?, 'Naledi Khumalo', 'freelancer', ?)")
    .bind(email, f.id)
    .run();
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  await setPassword(env, u.id, FREELANCER_PW);
  return { userId: u.id, freelancerId: f.id, email };
}

async function login(env, email, password) {
  const res = await worker.fetch(req("/login", { method: "POST", form: { email, password } }), env);
  return { res, session: setCookie(res, "c7_session") };
}

async function csrfFor(env, session) {
  const row = await env.DB.prepare("SELECT csrf_token FROM sessions WHERE token = ?").bind(session).first();
  return row.csrf_token;
}

async function founderSession(env) {
  const f = await seedFounder(env);
  const { session } = await login(env, f.email, FOUNDER_PW);
  return { ...f, session, csrf: await csrfFor(env, session) };
}

async function auditActions(env) {
  const { results } = await env.DB.prepare("SELECT action FROM audit_log ORDER BY id").all();
  return results.map((r) => r.action);
}

// ====================================================================== //
console.log("\nCatalyst 7 KPI — integration suite\n");
console.log("Auth & sessions");

await test("unauthenticated request redirects to /login", async () => {
  const env = makeEnv();
  const res = await worker.fetch(req("/"), env);
  eq(res.status, 302, "status");
  eq(res.headers.get("Location"), "/login", "location");
});

await test("GET /login renders the sign-in form", async () => {
  const env = makeEnv();
  const res = await worker.fetch(req("/login"), env);
  eq(res.status, 200, "status");
  const body = await res.text();
  has(body, 'action="/login"', "login form");
  has(body, 'name="password"', "password field");
});

await test("login with the wrong password is rejected and issues no session", async () => {
  const env = makeEnv();
  const f = await seedFounder(env);
  const { res, session } = await login(env, f.email, "not-the-password");
  eq(res.status, 401, "status");
  eq(session, null, "must not set a session cookie");
  has(await res.text(), "Incorrect email or password.", "error message");
});

await test("login with the right password issues a session", async () => {
  const env = makeEnv();
  const f = await seedFounder(env);
  const { res, session } = await login(env, f.email, FOUNDER_PW);
  eq(res.status, 302, "status");
  assert(session, "session cookie set");
  const raw = rawSetCookie(res, "c7_session");
  has(raw, "HttpOnly", "HttpOnly");
  has(raw, "Secure", "Secure");
  has(raw, "SameSite=Lax", "SameSite");
  const row = await env.DB.prepare("SELECT * FROM sessions WHERE token = ?").bind(session).first();
  assert(row && row.user_id === f.id, "session row persisted against the right user");
  assert(row.csrf_token && row.csrf_token.length >= 32, "session carries its own CSRF token");
});

await test("a signed-in founder lands on /dashboard", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const res = await worker.fetch(req("/", { cookies: { c7_session: session } }), env);
  eq(res.status, 302, "status");
  eq(res.headers.get("Location"), "/dashboard", "location");
});

await test("logout destroys the session row and clears the cookie", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const res = await worker.fetch(req("/logout", { cookies: { c7_session: session } }), env);
  eq(res.status, 302, "status");
  has(rawSetCookie(res, "c7_session"), "Max-Age=0", "cookie cleared");
  const row = await env.DB.prepare("SELECT * FROM sessions WHERE token = ?").bind(session).first();
  eq(row, null, "session row deleted");
  const after = await worker.fetch(req("/dashboard", { cookies: { c7_session: session } }), env);
  eq(after.headers.get("Location"), "/login", "old cookie no longer works");
});

console.log("\nFirst-time setup");

await test("an invalid setup token is refused", async () => {
  const env = makeEnv();
  const res = await worker.fetch(req("/setup/deadbeef"), env);
  eq(res.status, 404, "status");
  has(await res.text(), "invalid or has already been used", "message");
});

await test("setup sets the password, audits it, and signs the user in", async () => {
  const env = makeEnv();
  await env.DB.prepare("INSERT INTO users (email, name, role, setup_token) VALUES ('somila@catalyst7.co.za', 'Somila', 'founder', 'tok123')").run();

  const short = await worker.fetch(req("/setup/tok123", { method: "POST", form: { password: "abc", confirm: "abc" } }), env);
  eq(short.status, 400, "short password rejected");

  const mismatch = await worker.fetch(
    req("/setup/tok123", { method: "POST", form: { password: "longenough1", confirm: "different1" } }),
    env
  );
  eq(mismatch.status, 400, "mismatched confirmation rejected");

  const ok = await worker.fetch(req("/setup/tok123", { method: "POST", form: { password: "longenough1", confirm: "longenough1" } }), env);
  eq(ok.status, 302, "status");
  assert(setCookie(ok, "c7_session"), "session issued");
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = 'somila@catalyst7.co.za'").first();
  assert(u.password_hash && u.password_salt, "password hash + salt stored");
  lacks(u.password_hash, "longenough1", "plaintext password never stored");
  eq(u.setup_token, null, "setup token consumed");
  assert((await auditActions(env)).includes("account_activated"), "audit row written");
});

console.log("\nRate limiting");

await test("login is rate limited per account and per IP", async () => {
  const env = makeEnv();
  const f = await seedFounder(env);

  for (let i = 0; i < 5; i++) {
    const r = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: "wrong" } }), env);
    eq(r.status, 401, `attempt ${i + 1} should be a plain rejection`);
  }
  const blocked = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: "wrong" } }), env);
  eq(blocked.status, 429, "6th attempt on one account is blocked");
  has(await blocked.text(), "Too many attempts for this account", "per-account message");

  // Even the correct password stays blocked inside the window.
  const stillBlocked = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: FOUNDER_PW } }), env);
  eq(stillBlocked.status, 429, "correct password is still blocked during the lockout");

  // Per-IP limit: 20 distinct accounts, one failure each, from one address.
  const env2 = makeEnv();
  const ip = { "CF-Connecting-IP": "41.13.7.9" };
  for (let i = 0; i < 20; i++) {
    await worker.fetch(req("/login", { method: "POST", headers: ip, form: { email: `nobody${i}@example.com`, password: "x" } }), env2);
  }
  const ipBlocked = await worker.fetch(
    req("/login", { method: "POST", headers: ip, form: { email: "nobody99@example.com", password: "x" } }),
    env2
  );
  eq(ipBlocked.status, 429, "21st attempt from one IP is blocked");
  has(await ipBlocked.text(), "Too many attempts from this network", "per-network message");
});

console.log("\nCSRF");

await test("a mutating POST without a CSRF token is refused and writes nothing", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const res = await worker.fetch(req("/clients", { method: "POST", cookies: { c7_session: session }, form: { name: "Umlazi Foods" } }), env);
  eq(res.status, 403, "status");
  has(await res.text(), "Session expired or the form was stale", "message");
  const { results } = await env.DB.prepare("SELECT * FROM clients").all();
  eq(results.length, 0, "no client row written");
});

await test("a mutating POST with a stale CSRF token is refused", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const res = await worker.fetch(
    req("/clients", { method: "POST", cookies: { c7_session: session }, form: { name: "Umlazi Foods", _csrf: "not-the-right-token" } }),
    env
  );
  eq(res.status, 403, "status");
  const { results } = await env.DB.prepare("SELECT * FROM clients").all();
  eq(results.length, 0, "no client row written");
});

await test("a mutating POST with a valid CSRF token succeeds", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const res = await worker.fetch(
    req("/clients", { method: "POST", cookies: { c7_session: session }, form: { name: "Umlazi Foods", source: "referral", _csrf: csrf } }),
    env
  );
  eq(res.status, 302, "status");
  const clients = await db.getClients(env);
  eq(clients.length, 1, "one client row");
  eq(clients[0].name, "Umlazi Foods", "name persisted");
  assert((await auditActions(env)).includes("client_created"), "audit row written");
});

console.log("\nRole enforcement");

await test("a freelancer cannot reach founder-only routes", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  const { session } = await login(env, fl.email, FREELANCER_PW);
  for (const path of ["/dashboard", "/freelancers", "/clients", "/leads", "/revenue", "/audit", "/errors", "/retention"]) {
    const res = await worker.fetch(req(path, { cookies: { c7_session: session } }), env);
    eq(res.status, 404, `${path} must not be reachable by a freelancer`);
  }
});

await test("a freelancer lands on /log and sees only their own history", async () => {
  const env = makeEnv();
  const mine = await seedFreelancer(env, "naledi@example.com");
  const other = await seedFreelancer(env, "sipho@example.com");
  await db.upsertWeeklyEntry(env, { week_start: "2026-07-20", freelancer_id: mine.freelancerId, hours: 12, deliverables: "Mine" });
  await db.upsertWeeklyEntry(env, { week_start: "2026-07-20", freelancer_id: other.freelancerId, hours: 30, deliverables: "Theirs" });

  const { session } = await login(env, mine.email, FREELANCER_PW);
  const root = await worker.fetch(req("/", { cookies: { c7_session: session } }), env);
  eq(root.headers.get("Location"), "/log", "root redirect");

  const hist = await worker.fetch(req("/log/history", { cookies: { c7_session: session } }), env);
  eq(hist.status, 200, "history status");
  const body = await hist.text();
  has(body, "Mine", "own deliverable shown");
  lacks(body, "Theirs", "another freelancer's row must not leak");
});

console.log("\nRecords & audit trail");

await test("a founder can create a freelancer and it is audited", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const res = await worker.fetch(
    req("/freelancers", {
      method: "POST",
      cookies: { c7_session: session },
      form: { name: "Naledi Khumalo", email: "naledi@example.com", role_title: "Designer", rate_type: "hourly", rate_amount: "650", _csrf: csrf },
    }),
    env
  );
  eq(res.status, 302, "status");
  const rows = await db.getFreelancers(env);
  eq(rows.length, 1, "one freelancer");
  eq(rows[0].rate_amount, 650, "rate stored as a number");
  eq(rows[0].active, 1, "active by default");
  assert((await auditActions(env)).includes("freelancer_created"), "audit row written");
});

await test("freelancer invite mints a single-use setup link and audits it", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await db.createFreelancer(env, { name: "Naledi Khumalo", email: "naledi@example.com" });
  const f = (await db.getFreelancers(env))[0];

  const res = await worker.fetch(
    req(`/freelancers/${f.id}/invite`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(res.status, 200, "status");
  const body = await res.text();
  has(body, "/setup/", "invite link rendered");
  const invited = await env.DB.prepare("SELECT * FROM users WHERE freelancer_id = ?").bind(f.id).first();
  assert(invited && invited.setup_token, "user row created with a setup token");
  eq(invited.role, "freelancer", "invited as a freelancer");
  assert((await auditActions(env)).includes("freelancer_invited"), "audit row written");
});

await test("a lead can be created and moved through stages, with both steps audited", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await worker.fetch(
    req("/leads", {
      method: "POST",
      cookies: { c7_session: session },
      form: { name: "Zanele Buthelezi", company: "Rivonia Retail", value_estimate: "25000", owner: "Somila", _csrf: csrf },
    }),
    env
  );
  const lead = (await db.getLeads(env))[0];
  eq(lead.stage, "new", "defaults to new");
  eq(lead.value_estimate, 25000, "value parsed as a number");

  const res = await worker.fetch(
    req(`/leads/${lead.id}/stage`, { method: "POST", cookies: { c7_session: session }, form: { stage: "won", _csrf: csrf } }),
    env
  );
  eq(res.status, 302, "status");
  eq((await db.getLeads(env))[0].stage, "won", "stage persisted");
  const actions = await auditActions(env);
  assert(actions.includes("lead_created"), "creation audited");
  assert(actions.includes("lead_stage_changed"), "stage change audited");
});

await test("revenue entries feed the dashboard totals", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await db.createClient(env, { name: "Umlazi Foods" });
  const client = (await db.getClients(env))[0];

  await worker.fetch(
    req("/revenue", {
      method: "POST",
      cookies: { c7_session: session },
      form: { week_start: "2026-07-27", client_id: String(client.id), amount: "12400", type: "project", invoice_status: "paid", _csrf: csrf },
    }),
    env
  );
  await db.createRevenueEntry(env, { week_start: "2026-07-27", amount: 5000, type: "retainer" });
  await db.createRevenueEntry(env, { week_start: "2026-07-20", amount: 8000, type: "project" });

  const data = await db.getDashboard(env, "2026-07-27", "2026-07-20");
  eq(data.revThis, 17400, "this week's revenue");
  eq(data.revPrev, 8000, "last week's revenue");
  eq(data.revByType.length, 2, "grouped by type");
  assert((await auditActions(env)).includes("revenue_logged"), "audit row written");
});

await test("a weekly log submitted twice updates one row rather than duplicating", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  const { session } = await login(env, fl.email, FREELANCER_PW);
  const csrf = await csrfFor(env, session);

  await worker.fetch(
    req("/log", { method: "POST", cookies: { c7_session: session }, form: { hours: "10", deliverables: "First pass", status: "on_track", _csrf: csrf } }),
    env
  );
  await worker.fetch(
    req("/log", { method: "POST", cookies: { c7_session: session }, form: { hours: "18.5", deliverables: "Revised", status: "blocked", _csrf: csrf } }),
    env
  );

  const { results } = await env.DB.prepare("SELECT * FROM weekly_entries WHERE freelancer_id = ?").bind(fl.freelancerId).all();
  eq(results.length, 1, "still a single row for the week");
  eq(results[0].hours, 18.5, "hours updated");
  eq(results[0].status, "blocked", "status updated");
  eq(results[0].deliverables, "Revised", "deliverables updated");
});

await test("the dashboard reports who has not logged their week", async () => {
  const env = makeEnv();
  await db.createFreelancer(env, { name: "Logged Lerato" });
  await db.createFreelancer(env, { name: "Missing Mandla" });
  await db.createFreelancer(env, { name: "Inactive Ivan" });
  const all = await db.getFreelancers(env);
  const inactive = all.find((f) => f.name === "Inactive Ivan");
  await db.setFreelancerActive(env, inactive.id, false);
  const logged = all.find((f) => f.name === "Logged Lerato");
  await db.upsertWeeklyEntry(env, { week_start: "2026-07-27", freelancer_id: logged.id, hours: 20 });

  const data = await db.getDashboard(env, "2026-07-27", "2026-07-20");
  eq(data.activeFreelancerCount, 2, "inactive freelancers are excluded");
  eq(data.submittedCount, 1, "one submission");
  eq(data.missingFreelancers.length, 1, "one missing");
  eq(data.missingFreelancers[0].name, "Missing Mandla", "the right person is flagged");
  eq(data.hoursThis, 20, "hours aggregated");
});

await test("database CHECK constraints reject invalid enum values", async () => {
  const env = makeEnv();
  let rejectedStage = false;
  try {
    await env.DB.prepare("INSERT INTO leads (name, stage) VALUES (?, ?)").bind("Bad Lead", "not-a-stage").run();
  } catch {
    rejectedStage = true;
  }
  assert(rejectedStage, "invalid lead stage must be rejected at the database layer");

  let rejectedType = false;
  try {
    await env.DB.prepare("INSERT INTO revenue_entries (week_start, amount, type) VALUES (?, ?, ?)").bind("2026-07-27", 100, "bogus").run();
  } catch {
    rejectedType = true;
  }
  assert(rejectedType, "invalid revenue type must be rejected at the database layer");

  let rejectedRole = false;
  try {
    await env.DB.prepare("INSERT INTO users (email, name, role) VALUES (?, ?, ?)").bind("x@y.z", "X", "superadmin").run();
  } catch {
    rejectedRole = true;
  }
  assert(rejectedRole, "invalid user role must be rejected at the database layer");
});

console.log("\nTwo-factor authentication");

await test("2FA can be enabled from /security with a live authenticator code", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);

  const start = await worker.fetch(req("/security/2fa/start", { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }), env);
  eq(start.status, 302, "start status");
  let u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
  assert(u.totp_secret, "secret generated");
  eq(u.totp_enabled, 0, "not enabled until confirmed");

  const wrong = await worker.fetch(
    req("/security/2fa/confirm", { method: "POST", cookies: { c7_session: session }, form: { code: "000000", _csrf: csrf } }),
    env
  );
  eq(wrong.status, 400, "a wrong code does not enable 2FA");
  u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
  eq(u.totp_enabled, 0, "still not enabled");

  const code = await totpCodeNow(u.totp_secret);
  const ok = await worker.fetch(
    req("/security/2fa/confirm", { method: "POST", cookies: { c7_session: session }, form: { code, _csrf: csrf } }),
    env
  );
  eq(ok.status, 200, "confirm status");
  u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
  eq(u.totp_enabled, 1, "2FA enabled");
  assert((await auditActions(env)).includes("2fa_enabled"), "audit row written");
});

await test("with 2FA on, a correct password alone does not issue a session", async () => {
  const env = makeEnv();
  const f = await seedFounder(env);
  await env.DB.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?").bind(generateTotpSecret(), f.id).run();

  const res = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: FOUNDER_PW } }), env);
  eq(res.status, 302, "status");
  eq(res.headers.get("Location"), "/login/2fa", "routed to the 2FA step");
  eq(setCookie(res, "c7_session"), null, "no session cookie yet");
  assert(setCookie(res, "c7_pending"), "short-lived pending cookie issued");
});

await test("the 2FA step rejects a wrong code and accepts the real one", async () => {
  const env = makeEnv();
  const f = await seedFounder(env);
  const secret = generateTotpSecret();
  await env.DB.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?").bind(secret, f.id).run();

  const first = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: FOUNDER_PW } }), env);
  const pending = setCookie(first, "c7_pending");

  const wrong = await worker.fetch(req("/login/2fa", { method: "POST", cookies: { c7_pending: pending }, form: { code: "000000" } }), env);
  eq(wrong.status, 401, "wrong code rejected");
  eq(setCookie(wrong, "c7_session"), null, "no session on a wrong code");

  const code = await totpCodeNow(secret);
  const ok = await worker.fetch(req("/login/2fa", { method: "POST", cookies: { c7_pending: pending }, form: { code } }), env);
  eq(ok.status, 302, "correct code accepted");
  const session = setCookie(ok, "c7_session");
  assert(session, "session issued");
  const row = await env.DB.prepare("SELECT * FROM sessions WHERE token = ?").bind(session).first();
  assert(row, "session row persisted");
  const leftover = await env.DB.prepare("SELECT * FROM pending_logins WHERE token = ?").bind(pending).first();
  eq(leftover, null, "pending login consumed");
});

console.log("\nRetention & erasure");

await test("the monthly scan flags stale records and never double-flags", async () => {
  const env = makeEnv();
  await env.DB.prepare(
    "INSERT INTO leads (name, company, contact_email, stage, updated_at) VALUES ('Old Lead', 'Dormant Co', 'old@example.com', 'lost', date('now', '-400 days'))"
  ).run();
  await env.DB.prepare("INSERT INTO leads (name, stage, updated_at) VALUES ('Recent Loss', 'lost', date('now', '-10 days'))").run();
  await env.DB.prepare("INSERT INTO leads (name, stage) VALUES ('Live Lead', 'qualified')").run();
  await env.DB.prepare("INSERT INTO freelancers (name, active) VALUES ('Dormant Dineo', 0)").run();
  await env.DB.prepare("INSERT INTO freelancers (name, active) VALUES ('Working Wandile', 1)").run();

  const first = await db.runRetentionScan(env);
  eq(first.leadsFlagged, 1, "only the stale lost lead is flagged");
  eq(first.freelancersFlagged, 1, "only the dormant freelancer is flagged");

  let flags = await db.getOpenRetentionFlags(env);
  eq(flags.length, 2, "two open flags");
  assert(
    flags.some((f) => f.label === "Old Lead (Dormant Co)"),
    "flag carries a human-readable label"
  );

  await db.runRetentionScan(env);
  flags = await db.getOpenRetentionFlags(env);
  eq(flags.length, 2, "re-running the scan does not duplicate open flags");

  const { results } = await env.DB.prepare("SELECT * FROM leads WHERE name = 'Old Lead'").all();
  eq(results[0].contact_email, "old@example.com", "the scan itself never erases anything");
});

await test('resolving a flag as "erase" clears PII, keeps the row, and audits it', async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await env.DB.prepare(
    "INSERT INTO leads (name, company, contact_email, notes, stage, value_estimate) VALUES ('Old Lead', 'Dormant Co', 'old@example.com', 'private notes', 'lost', 4200)"
  ).run();
  const lead = (await db.getLeads(env))[0];
  await db.flagForRetentionReview(env, "lead", lead.id, "Lost lead, no activity in 365+ days");
  const flag = (await db.getOpenRetentionFlags(env))[0];

  const res = await worker.fetch(
    req(`/retention/${flag.id}/resolve`, { method: "POST", cookies: { c7_session: session }, form: { decision: "erase", _csrf: csrf } }),
    env
  );
  eq(res.status, 302, "status");

  const after = await env.DB.prepare("SELECT * FROM leads WHERE id = ?").bind(lead.id).first();
  assert(after, "the row itself is kept, not deleted");
  eq(after.name, "[erased]", "name cleared");
  eq(after.contact_email, null, "contact email cleared");
  eq(after.company, null, "company cleared");
  eq(after.notes, null, "notes cleared");
  eq(after.value_estimate, 4200, "financial history preserved");

  const resolved = await env.DB.prepare("SELECT * FROM retention_flags WHERE id = ?").bind(flag.id).first();
  eq(resolved.resolved, 1, "flag closed");
  eq(resolved.resolution, "erased", "resolution recorded");
  assert((await auditActions(env)).includes("retention_erased"), "audit row written");
});

await test('resolving a flag as "keep" leaves the record untouched', async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await env.DB.prepare("INSERT INTO leads (name, company, contact_email, stage) VALUES ('Old Lead', 'Dormant Co', 'old@example.com', 'lost')").run();
  const lead = (await db.getLeads(env))[0];
  await db.flagForRetentionReview(env, "lead", lead.id, "Lost lead, no activity in 365+ days");
  const flag = (await db.getOpenRetentionFlags(env))[0];

  await worker.fetch(
    req(`/retention/${flag.id}/resolve`, { method: "POST", cookies: { c7_session: session }, form: { decision: "keep", _csrf: csrf } }),
    env
  );

  const after = await env.DB.prepare("SELECT * FROM leads WHERE id = ?").bind(lead.id).first();
  eq(after.name, "Old Lead", "name intact");
  eq(after.contact_email, "old@example.com", "contact email intact");
  const resolved = await env.DB.prepare("SELECT * FROM retention_flags WHERE id = ?").bind(flag.id).first();
  eq(resolved.resolution, "kept", "resolution recorded");
  eq((await db.getOpenRetentionFlags(env)).length, 0, "queue is empty again");
  assert((await auditActions(env)).includes("retention_kept"), "audit row written");
});

await test("erasing a freelancer clears their linked login too", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  await db.eraseFreelancerPII(env, fl.freelancerId);

  const f = await db.getFreelancerById(env, fl.freelancerId);
  eq(f.name, "[erased]", "freelancer name cleared");
  eq(f.email, null, "freelancer email cleared");
  const u = await env.DB.prepare("SELECT * FROM users WHERE freelancer_id = ?").bind(fl.freelancerId).first();
  eq(u.name, "[erased]", "login name cleared");
  has(u.email, "@placeholder.local", "login email replaced with a non-routable placeholder");
});

console.log("\nTheme (server-driven dark/light)");

await test("/theme/toggle is public and flips dark to light", async () => {
  const env = makeEnv();
  const res = await worker.fetch(req("/theme/toggle"), env);
  eq(res.status, 302, "status");
  eq(res.headers.get("Location"), "/", "default destination");
  const raw = rawSetCookie(res, "c7_theme");
  has(raw, "c7_theme=light", "flips to light");
  has(raw, "HttpOnly", "HttpOnly");
  has(raw, "Secure", "Secure");
  has(raw, "SameSite=Lax", "SameSite");
  has(raw, "Max-Age=31536000", "one-year lifetime");
});

await test("/theme/toggle flips light back to dark", async () => {
  const env = makeEnv();
  const res = await worker.fetch(req("/theme/toggle", { cookies: { c7_theme: "light" } }), env);
  has(rawSetCookie(res, "c7_theme"), "c7_theme=dark", "flips back to dark");
});

await test("/theme/toggle returns to the same-origin page it was called from", async () => {
  const env = makeEnv();
  const res = await worker.fetch(req("/theme/toggle", { headers: { Referer: `${ORIGIN}/leads?stage=won` } }), env);
  eq(res.headers.get("Location"), "/leads?stage=won", "path and query preserved");
});

await test("/theme/toggle ignores a cross-origin Referer", async () => {
  const env = makeEnv();
  const evil = await worker.fetch(req("/theme/toggle", { headers: { Referer: "https://evil.example.com/phish" } }), env);
  eq(evil.headers.get("Location"), "/", "no open redirect");
  const junk = await worker.fetch(req("/theme/toggle", { headers: { Referer: "not a url" } }), env);
  eq(junk.headers.get("Location"), "/", "malformed Referer is ignored");
});

await test("the theme cookie drives the rendered page on public pages", async () => {
  const env = makeEnv();
  const dark = await worker.fetch(req("/login"), env);
  const darkBody = await dark.text();
  has(darkBody, '<html lang="en" data-theme="dark">', "defaults to dark");
  has(darkBody, 'href="/theme/toggle"', "toggle link present when signed out");

  const light = await worker.fetch(req("/login", { cookies: { c7_theme: "light" } }), env);
  has(await light.text(), '<html lang="en" data-theme="light">', "honours the light cookie");

  const junk = await worker.fetch(req("/login", { cookies: { c7_theme: "chartreuse" } }), env);
  has(await junk.text(), '<html lang="en" data-theme="dark">', "an unknown value falls back to dark");
});

await test("the theme cookie drives every authenticated page too", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  for (const path of ["/dashboard", "/freelancers", "/clients", "/leads", "/revenue", "/audit", "/errors", "/retention", "/security"]) {
    const res = await worker.fetch(req(path, { cookies: { c7_session: session, c7_theme: "light" } }), env);
    eq(res.status, 200, `${path} status`);
    const body = await res.text();
    has(body, '<html lang="en" data-theme="light">', `${path} must honour the theme cookie`);
    has(body, 'href="/theme/toggle"', `${path} must offer the toggle`);
  }
});

console.log("\nCSS-only interaction markup");

// The suite is otherwise data-focused. These two guard the pure-CSS patterns
// that have no JS to break loudly -- they fail silently in a browser, so they
// are worth asserting on the emitted markup.

await test("the mobile menu rule is scoped to the mobile breakpoint", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const body = await (await worker.fetch(req("/dashboard", { cookies: { c7_session: session } }), env)).text();

  const media = body.match(/@media \(max-width:859px\)\{([\s\S]*?)\n\}/);
  assert(media, "the 859px breakpoint block should exist");
  has(media[1], ".hamburger-toggle:checked ~ .mobile-menu", "the checked rule must live inside the breakpoint");

  // Outside the media block there must be no unscoped version, or the menu
  // stays open behind the desktop nav when the viewport widens.
  const outside = body.replace(media[0], "");
  lacks(outside, ".hamburger-toggle:checked ~ .mobile-menu", "no unscoped checked rule");
  has(body, '<input type="checkbox" id="navtoggle"', "nav checkbox present");
  has(body, 'for="navtoggle"', "hamburger label bound to the checkbox");
});

await test("every add-form page emits the checkbox before its sibling panel", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  for (const path of ["/freelancers", "/clients", "/leads", "/revenue"]) {
    const body = await (await worker.fetch(req(path, { cookies: { c7_session: session } }), env)).text();
    const cb = body.indexOf('id="add-toggle"');
    const head = body.indexOf('class="page-head-row"');
    const panel = body.indexOf('class="panel add-panel"');
    assert(cb !== -1, `${path}: toggle checkbox present`);
    assert(head !== -1, `${path}: page head row present`);
    assert(panel !== -1, `${path}: collapsible panel present`);
    // `~` is a following-sibling combinator: the checkbox must come first.
    assert(cb < head && head < panel, `${path}: checkbox must precede the head row and the panel`);
    has(body, 'for="add-toggle"', `${path}: a label is bound to the toggle`);
  }
});

// ------------------------------------------------------------------ report --

const total = passed + failures.length;
console.log(`\n${"-".repeat(52)}`);
if (failures.length === 0) {
  console.log(`${passed}/${total} tests passed.\n`);
  process.exit(0);
} else {
  console.log(`${passed}/${total} passed, ${failures.length} FAILED:\n`);
  for (const f of failures) console.log(`  - ${f.name}\n    ${f.err.message}`);
  console.log("");
  process.exit(1);
}
