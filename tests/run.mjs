// End-to-end integration tests for Catalyst 7 KPI.
//
// These drive the real Worker (`src/index.js`) with real Request objects
// against a real SQLite engine (`node:sqlite`, wrapped to look like D1 --
// see tests/d1.mjs). Nothing here is mocked or reimplemented.
//
// No test framework: `node tests/run.mjs`.
// On Node 20/22 add --experimental-sqlite; on Node 23+ node:sqlite is on by
// default and the flag is unnecessary.

// Defaults to the real source tree. Set TEST_TARGET=../dist/worker.js to run
// this same suite against the single-file dashboard build, which is how that
// build is verified to be equivalent (see tests/bundle.mjs).
const TARGET = process.env.TEST_TARGET || "../src/index.js";
const worker = (await import(TARGET)).default;

import {
  setPassword,
  totpCodeNow,
  generateTotpSecret,
  hashBackupCode,
  normalizeBackupCode,
  callWindowHours,
} from "../src/auth.js";
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
  if (form) {
    // Mirror what a real rendered form sends: csrfField() emits _csrf AND a
    // fresh _nonce together, so any form carrying a CSRF token carries a
    // nonce too. Tests that want to exercise a *replayed* submission pass
    // _nonce explicitly.
    const body = { ...form };
    if (body._csrf !== undefined && body._nonce === undefined) body._nonce = crypto.randomUUID();
    init.body = new URLSearchParams(body);
  }
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

// ------------------------------------------------------------ google stubs --

const GOOGLE_CLIENT_ID = "test-client.apps.googleusercontent.com";

function googleEnv() {
  const env = makeEnv();
  env.GOOGLE_CLIENT_ID = GOOGLE_CLIENT_ID;
  env.GOOGLE_CLIENT_SECRET = "test-client-secret";
  return env;
}

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

// The signature is never inspected -- see validateGoogleIdToken's comment on
// why a token fetched directly from Google's endpoint over TLS isn't
// re-verified locally. These tests exercise the claim checks.
function fakeIdToken(claims) {
  return `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url(claims)}.sig`;
}

function googleClaims(overrides = {}) {
  return {
    iss: "https://accounts.google.com",
    aud: GOOGLE_CLIENT_ID,
    sub: "1029384756",
    email: "thembalethu@catalyst7.co.za",
    email_verified: true,
    exp: Math.floor(Date.now() / 1000) + 600,
    ...overrides,
  };
}

// Intercepts only Google's token endpoint; anything else falls through.
function stubGoogleTokenEndpoint(idToken, { status = 200, body = null } = {}) {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (input, init) => {
    if (String(input).includes("oauth2.googleapis.com/token")) {
      calls++;
      const payload = body !== null ? body : JSON.stringify({ id_token: idToken, token_type: "Bearer" });
      return new Response(payload, { status, headers: { "Content-Type": "application/json" } });
    }
    return original(input, init);
  };
  return {
    restore: () => {
      globalThis.fetch = original;
    },
    get calls() {
      return calls;
    },
  };
}

// Walks the front half of the handshake and hands back the live state/nonce.
async function beginGoogleHandshake(env) {
  const res = await worker.fetch(req("/auth/google"), env);
  eq(res.status, 302, "auth start should redirect to Google");
  const dest = new URL(res.headers.get("Location"));
  const state = dest.searchParams.get("state");
  const row = await env.DB.prepare("SELECT * FROM oauth_states WHERE state = ?").bind(state).first();
  return { res, dest, state, row };
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
  has(raw, "Secure", "Secure");
  has(raw, "SameSite=Lax", "SameSite");
  has(raw, "Max-Age=31536000", "one-year lifetime");
  // Deliberately NOT HttpOnly, unlike the session cookie. The in-page toggle
  // writes this via document.cookie for an instant switch, and a browser
  // silently drops that write if an HttpOnly cookie of the same name exists --
  // the theme would snap back on the next load. It carries no secret.
  lacks(raw, "HttpOnly", "theme cookie must stay readable by the page");
  has(rawSetCookie(await worker.fetch(req("/login"), env), "c7_session") || "none", "none", "sanity: no session cookie here");
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

await test("the theme switch works instantly in-page, and still works without JS", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const body = await (await worker.fetch(req("/dashboard", { cookies: { c7_session: session } }), env)).text();

  // The no-JS path: a real link to the server route, so the toggle keeps
  // working if the script is blocked or fails.
  has(body, 'href="/theme/toggle"', "server fallback link present");
  has(body, "data-theme-toggle", "hook the script binds to");

  const script = body.match(/<script>([\s\S]*?)<\/script>/);
  assert(script, "the enhancement script is on the page");
  has(script[1], "preventDefault", "it takes over the click rather than following the link");
  has(script[1], "document.cookie", "it persists the choice itself, so there's no round-trip");
  has(script[1], "dataset.theme", "it flips the attribute the CSS keys off");
  lacks(script[1], "fetch(", "no network call -- connect-src stays 'none'");
  lacks(script[1], "HttpOnly", "the cookie it writes cannot be HttpOnly");

  // Modified clicks must fall through to normal browser behaviour.
  has(script[1], "metaKey", "ctrl/cmd-click still opens normally");

  // And the whole thing must be exactly one small script, not a bundle.
  eq((body.match(/<script/g) || []).length, 1, "exactly one script tag on the page");
  assert(script[1].length < 800, `script stays tiny (${script[1].length} bytes)`);
  lacks(body, "<script src", "no external script is ever loaded");
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

console.log("\nGoogle sign-in");

await test("Google routes stay dark when no client is configured", async () => {
  const env = makeEnv(); // no GOOGLE_CLIENT_ID / SECRET
  const start = await worker.fetch(req("/auth/google"), env);
  eq(start.status, 404, "start route is not exposed");
  const cb = await worker.fetch(req("/auth/google/callback?code=x&state=y"), env);
  eq(cb.status, 404, "callback is not exposed");
  const login = await (await worker.fetch(req("/login"), env)).text();
  lacks(login, "/auth/google", "no Google button on the sign-in page");
  has(login, 'action="/login"', "password form still there");
});

await test("the sign-in page offers Google once a client is configured", async () => {
  const env = googleEnv();
  const body = await (await worker.fetch(req("/login"), env)).text();
  has(body, 'href="/auth/google"', "Google button rendered");
  has(body, "Continue with Google", "button label");
  has(body, "<svg", "Google mark is inlined, not fetched");
  lacks(body, "https://www.google.com", "no external asset requests");
});

await test("/auth/google builds a correct authorization request", async () => {
  const env = googleEnv();
  const { dest, state, row } = await beginGoogleHandshake(env);

  eq(dest.origin + dest.pathname, "https://accounts.google.com/o/oauth2/v2/auth", "Google endpoint");
  eq(dest.searchParams.get("client_id"), GOOGLE_CLIENT_ID, "client id");
  eq(dest.searchParams.get("response_type"), "code", "authorization code flow");
  eq(dest.searchParams.get("redirect_uri"), `${ORIGIN}/auth/google/callback`, "redirect uri");
  eq(dest.searchParams.get("code_challenge_method"), "S256", "PKCE method");
  assert(dest.searchParams.get("code_challenge"), "PKCE challenge present");
  assert(dest.searchParams.get("scope").includes("openid"), "openid scope");
  lacks(dest.searchParams.get("scope"), "offline", "no offline access requested");

  assert(row, "handshake persisted server-side");
  eq(row.state, state, "state matches");
  assert(row.nonce && row.nonce.length >= 16, "nonce generated");
  assert(row.code_verifier && row.code_verifier.length >= 32, "verifier stored server-side, never sent to the browser");
  eq(dest.searchParams.get("nonce"), row.nonce, "nonce forwarded to Google");
  lacks(dest.search, row.code_verifier, "raw verifier is never put in the URL");
});

await test("a known user is signed in and their Google account is bound", async () => {
  const env = googleEnv();
  const f = await seedFounder(env);
  const { state, row } = await beginGoogleHandshake(env);
  const stub = stubGoogleTokenEndpoint(fakeIdToken(googleClaims({ nonce: row.nonce, email: f.email })));
  try {
    const res = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
    eq(res.status, 302, "signed in");
    eq(res.headers.get("Location"), "/", "lands on the app");
    const session = setCookie(res, "c7_session");
    assert(session, "session cookie issued");
    eq(stub.calls, 1, "token endpoint called exactly once");

    const u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(f.id).first();
    eq(u.google_sub, "1029384756", "google_sub bound on first use");
    const actions = await auditActions(env);
    assert(actions.includes("google_account_linked"), "link audited");
    assert(actions.includes("login_google"), "login audited");
  } finally {
    stub.restore();
  }
});

await test("a Google account that isn't in the users table is refused", async () => {
  const env = googleEnv();
  await seedFounder(env); // a different, known account exists
  const { state, row } = await beginGoogleHandshake(env);
  const stub = stubGoogleTokenEndpoint(
    fakeIdToken(googleClaims({ nonce: row.nonce, email: "stranger@gmail.com", sub: "999" }))
  );
  try {
    const res = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
    eq(res.status, 403, "refused");
    eq(setCookie(res, "c7_session"), null, "no session issued");
    has(await res.text(), "authorised for this app", "explains why");

    const { results } = await env.DB.prepare("SELECT * FROM users WHERE email = 'stranger@gmail.com'").all();
    eq(results.length, 0, "no account is auto-provisioned");
    assert((await auditActions(env)).includes("login_google_denied"), "denial audited");
    const attempt = await env.DB.prepare("SELECT * FROM login_attempts WHERE email = 'stranger@gmail.com'").first();
    assert(attempt && attempt.success === 0, "counts against the rate limiter");
  } finally {
    stub.restore();
  }
});

await test("a callback state can only be redeemed once", async () => {
  const env = googleEnv();
  const f = await seedFounder(env);
  const { state, row } = await beginGoogleHandshake(env);
  const stub = stubGoogleTokenEndpoint(fakeIdToken(googleClaims({ nonce: row.nonce, email: f.email })));
  try {
    const first = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
    eq(first.status, 302, "first redemption works");
    const replay = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
    eq(replay.status, 400, "replayed callback is rejected");
    eq(setCookie(replay, "c7_session"), null, "no session from a replay");
    const left = await env.DB.prepare("SELECT * FROM oauth_states WHERE state = ?").bind(state).first();
    eq(left, null, "handshake row consumed");
  } finally {
    stub.restore();
  }
});

await test("an unknown or forged state is rejected outright", async () => {
  const env = googleEnv();
  await seedFounder(env);
  const stub = stubGoogleTokenEndpoint(fakeIdToken(googleClaims()));
  try {
    const res = await worker.fetch(req("/auth/google/callback?code=abc&state=made-up-state"), env);
    eq(res.status, 400, "rejected");
    eq(stub.calls, 0, "we never even talk to Google without a valid handshake");
    eq(setCookie(res, "c7_session"), null, "no session");
  } finally {
    stub.restore();
  }
});

await test("ID token claim checks reject tampered or replayed tokens", async () => {
  const cases = [
    ["nonce mismatch (replay)", { nonce: "not-the-nonce" }, 401],
    ["issued for another client", { aud: "someone-elses-client.apps.googleusercontent.com" }, 401],
    ["expired token", { exp: Math.floor(Date.now() / 1000) - 60 }, 401],
    ["unverified email", { email_verified: false }, 401],
    ["wrong issuer", { iss: "https://evil.example.com" }, 401],
  ];
  for (const [label, override, expected] of cases) {
    const env = googleEnv();
    const f = await seedFounder(env);
    const { state, row } = await beginGoogleHandshake(env);
    const claims = googleClaims({ nonce: row.nonce, email: f.email, ...override });
    const stub = stubGoogleTokenEndpoint(fakeIdToken(claims));
    try {
      const res = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
      eq(res.status, expected, `${label}: status`);
      eq(setCookie(res, "c7_session"), null, `${label}: must not issue a session`);
    } finally {
      stub.restore();
    }
  }
});

await test("a bound account rejects a different Google subject on the same email", async () => {
  const env = googleEnv();
  const f = await seedFounder(env);
  await db.bindGoogleSub(env, f.id, "the-original-sub");
  const { state, row } = await beginGoogleHandshake(env);
  const stub = stubGoogleTokenEndpoint(
    fakeIdToken(googleClaims({ nonce: row.nonce, email: f.email, sub: "a-different-sub" }))
  );
  try {
    const res = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
    eq(res.status, 403, "refused");
    eq(setCookie(res, "c7_session"), null, "no session");
    assert((await auditActions(env)).includes("login_google_sub_mismatch"), "mismatch audited");
    const u = await env.DB.prepare("SELECT google_sub FROM users WHERE id = ?").bind(f.id).first();
    eq(u.google_sub, "the-original-sub", "the original binding is not overwritten");
  } finally {
    stub.restore();
  }
});

await test("Google sign-in still has to clear 2FA when it is enabled", async () => {
  const env = googleEnv();
  const f = await seedFounder(env);
  const secret = generateTotpSecret();
  await env.DB.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?").bind(secret, f.id).run();

  const { state, row } = await beginGoogleHandshake(env);
  const stub = stubGoogleTokenEndpoint(fakeIdToken(googleClaims({ nonce: row.nonce, email: f.email })));
  try {
    const res = await worker.fetch(req(`/auth/google/callback?code=abc&state=${state}`), env);
    eq(res.status, 302, "status");
    eq(res.headers.get("Location"), "/login/2fa", "routed through the second factor");
    eq(setCookie(res, "c7_session"), null, "federated login does not bypass 2FA");
    assert(setCookie(res, "c7_pending"), "pending cookie issued");
  } finally {
    stub.restore();
  }
});

console.log("\n2FA backup codes");

// Walks the real enable flow and returns the codes as the user would see them.
async function enable2fa(env, session, csrf) {
  await worker.fetch(req("/security/2fa/start", { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }), env);
  const row = await env.DB.prepare("SELECT totp_secret FROM users WHERE totp_secret IS NOT NULL").first();
  const res = await worker.fetch(
    req("/security/2fa/confirm", {
      method: "POST",
      cookies: { c7_session: session },
      form: { code: await totpCodeNow(row.totp_secret), _csrf: csrf },
    }),
    env
  );
  const body = await res.text();
  const codes = [...body.matchAll(/<div class="code-chip">([A-Z0-9-]+)<\/div>/g)].map((m) => m[1]);
  return { secret: row.totp_secret, codes, body };
}

await test("enabling 2FA issues ten backup codes, shown once and stored hashed", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);
  const { codes, body } = await enable2fa(env, session, csrf);

  eq(codes.length, 10, "ten codes issued");
  eq(new Set(codes).size, 10, "all distinct");
  has(body, "only time they'll be shown", "warned that this is the one showing");
  for (const c of codes) assert(/^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(c), `well-formed code: ${c}`);

  const { results } = await env.DB.prepare("SELECT * FROM totp_backup_codes WHERE user_id = ?").bind(id).all();
  eq(results.length, 10, "ten rows stored");
  const stored = results.map((r) => r.code_hash);
  for (const c of codes) {
    lacks(stored.join("|"), normalizeBackupCode(c), "plaintext code must never be stored");
    assert(stored.includes(await hashBackupCode(c)), "hash of the shown code is on file");
  }
  eq(await db.countUnusedBackupCodes(env, id), 10, "all unused");

  // Revisiting the page must not re-reveal them.
  const revisit = await (await worker.fetch(req("/security", { cookies: { c7_session: session } }), env)).text();
  for (const c of codes) lacks(revisit, c, "codes are not shown again on reload");
  has(revisit, "10", "remaining count is shown instead");
  assert((await auditActions(env)).includes("2fa_backup_codes_generated"), "generation audited");
});

await test("a backup code signs you in and then cannot be reused", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);
  const { codes } = await enable2fa(env, session, csrf);
  const f = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();

  const first = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: FOUNDER_PW } }), env);
  const pending = setCookie(first, "c7_pending");

  const used = codes[3];
  const ok = await worker.fetch(req("/login/2fa", { method: "POST", cookies: { c7_pending: pending }, form: { code: used } }), env);
  eq(ok.status, 302, "backup code accepted in place of a TOTP code");
  assert(setCookie(ok, "c7_session"), "session issued");
  eq(await db.countUnusedBackupCodes(env, id), 9, "one code consumed");
  assert((await auditActions(env)).includes("2fa_backup_code_used"), "redemption audited");

  // Same code again, fresh pending login.
  const second = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: FOUNDER_PW } }), env);
  const pending2 = setCookie(second, "c7_pending");
  const replay = await worker.fetch(
    req("/login/2fa", { method: "POST", cookies: { c7_pending: pending2 }, form: { code: used } }),
    env
  );
  eq(replay.status, 401, "a spent code is rejected");
  eq(setCookie(replay, "c7_session"), null, "no session from a spent code");
  eq(await db.countUnusedBackupCodes(env, id), 9, "count unchanged by the failed replay");
});

await test("backup codes are accepted regardless of case and dashes", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);
  const { codes } = await enable2fa(env, session, csrf);
  const f = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();

  const login = await worker.fetch(req("/login", { method: "POST", form: { email: f.email, password: FOUNDER_PW } }), env);
  const pending = setCookie(login, "c7_pending");
  const messy = "  " + codes[0].toLowerCase().replace("-", "") + " ";
  const res = await worker.fetch(req("/login/2fa", { method: "POST", cookies: { c7_pending: pending }, form: { code: messy } }), env);
  eq(res.status, 302, "retyped code still works");
  eq(await db.countUnusedBackupCodes(env, id), 9, "consumed exactly one");
});

await test("regenerating replaces the whole set, and disabling 2FA clears it", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);
  const { codes: original } = await enable2fa(env, session, csrf);

  const regen = await worker.fetch(
    req("/security/2fa/backup-codes", { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(regen.status, 200, "status");
  const fresh = [...(await regen.text()).matchAll(/<div class="code-chip">([A-Z0-9-]+)<\/div>/g)].map((m) => m[1]);
  eq(fresh.length, 10, "a new set of ten");
  eq(original.filter((c) => fresh.includes(c)).length, 0, "no code carried over");
  eq(await db.countUnusedBackupCodes(env, id), 10, "exactly ten live codes");

  const stored = (await env.DB.prepare("SELECT code_hash FROM totp_backup_codes WHERE user_id = ?").bind(id).all()).results.map(
    (r) => r.code_hash
  );
  for (const c of original) lacks(stored.join("|"), await hashBackupCode(c), "old codes are gone from the database");
  assert((await auditActions(env)).includes("2fa_backup_codes_regenerated"), "regeneration audited");

  await worker.fetch(req("/security/2fa/disable", { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }), env);
  eq(await db.countUnusedBackupCodes(env, id), 0, "disabling 2FA clears the codes");
});

await test("backup code endpoints are behind CSRF and require 2FA to be on", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);

  const noCsrf = await worker.fetch(req("/security/2fa/backup-codes", { method: "POST", cookies: { c7_session: session } }), env);
  eq(noCsrf.status, 403, "no token, no codes");
  eq(await db.countUnusedBackupCodes(env, id), 0, "nothing generated");

  const notEnabled = await worker.fetch(
    req("/security/2fa/backup-codes", { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(notEnabled.status, 400, "refused while 2FA is off");
  eq(await db.countUnusedBackupCodes(env, id), 0, "still nothing generated");
});

console.log("\nTeam / user accounts");

function inviteLinkFrom(body) {
  const m = body.match(/\/setup\/([a-f0-9]{48,})/);
  return m ? m[1] : null;
}

await test("a founder can create another founder and gets a one-time invite link", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);

  const res = await worker.fetch(
    req("/team", {
      method: "POST",
      cookies: { c7_session: session },
      form: { name: "Somila", email: "Somila@Catalyst7.co.za", role: "founder", _csrf: csrf },
    }),
    env
  );
  eq(res.status, 200, "status");
  const body = await res.text();
  const token = inviteLinkFrom(body);
  assert(token, "invite link rendered");

  const created = await db.getUserByEmail(env, "somila@catalyst7.co.za");
  assert(created, "email is normalised to lowercase before storing");
  eq(created.role, "founder", "role applied");
  eq(created.has_password, 0, "no password until they set one");
  const raw = await env.DB.prepare("SELECT setup_token FROM users WHERE id = ?").bind(created.id).first();
  eq(raw.setup_token, token, "token matches the link shown");
  assert((await auditActions(env)).includes("founder_created"), "creation audited");

  // The link actually works end to end.
  const setup = await worker.fetch(
    req(`/setup/${token}`, { method: "POST", form: { password: "somilas-password", confirm: "somilas-password" } }),
    env
  );
  eq(setup.status, 302, "new founder can activate");
  assert(setCookie(setup, "c7_session"), "and is signed straight in");
  const after = await env.DB.prepare(
    "SELECT password_hash, setup_token FROM users WHERE email = 'somila@catalyst7.co.za'"
  ).first();
  assert(after.password_hash, "password set");
  eq(after.setup_token, null, "token consumed");
});

await test("the new founder really does get founder-level access", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const created = await worker.fetch(
    req("/team", { method: "POST", cookies: { c7_session: session }, form: { name: "Somila", email: "somila@catalyst7.co.za", role: "founder", _csrf: csrf } }),
    env
  );
  const token = inviteLinkFrom(await created.text());
  const setup = await worker.fetch(
    req(`/setup/${token}`, { method: "POST", form: { password: "somilas-password", confirm: "somilas-password" } }),
    env
  );
  const theirSession = setCookie(setup, "c7_session");

  for (const p of ["/dashboard", "/revenue", "/team", "/audit"]) {
    const r = await worker.fetch(req(p, { cookies: { c7_session: theirSession } }), env);
    eq(r.status, 200, `${p} reachable by the new founder`);
  }
});

await test("creating a freelancer login requires a real freelancer profile", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);

  const noProfile = await worker.fetch(
    req("/team", { method: "POST", cookies: { c7_session: session }, form: { name: "Naledi", email: "naledi@example.com", role: "freelancer", _csrf: csrf } }),
    env
  );
  eq(noProfile.status, 400, "refused without a linked profile");
  eq(await db.getUserByEmail(env, "naledi@example.com"), null, "nothing created");

  await db.createFreelancer(env, { name: "Naledi Khumalo" });
  const fl = (await db.getFreelancers(env))[0];
  const ok = await worker.fetch(
    req("/team", {
      method: "POST",
      cookies: { c7_session: session },
      form: { name: "Naledi", email: "naledi@example.com", role: "freelancer", freelancer_id: String(fl.id), _csrf: csrf },
    }),
    env
  );
  eq(ok.status, 200, "accepted with a profile");
  const created = await db.getUserByEmail(env, "naledi@example.com");
  eq(created.freelancer_id, fl.id, "linked to the profile");
  eq(created.role, "freelancer", "role applied");

  // That profile is no longer offered for a second login.
  eq((await db.getFreelancersWithoutUser(env)).length, 0, "already-linked profiles drop out of the picker");
});

await test("the add-person form validates and refuses duplicates", async () => {
  const env = makeEnv();
  const f = await seedFounder(env);
  const { session } = await login(env, f.email, FOUNDER_PW);
  const csrf = await csrfFor(env, session);
  const post = (form) => worker.fetch(req("/team", { method: "POST", cookies: { c7_session: session }, form: { ...form, _csrf: csrf } }), env);

  eq((await post({ name: "", email: "x@y.co", role: "founder" })).status, 400, "name required");
  eq((await post({ name: "X", email: "", role: "founder" })).status, 400, "email required");
  eq((await post({ name: "X", email: "not-an-email", role: "founder" })).status, 400, "email must look like one");
  eq((await post({ name: "X", email: "x@y.co", role: "superuser" })).status, 400, "role must be founder or freelancer");
  eq((await post({ name: "Dupe", email: f.email, role: "founder" })).status, 409, "duplicate email refused");

  const { results } = await env.DB.prepare("SELECT * FROM users").all();
  eq(results.length, 1, "no junk accounts created by any of that");
});

await test("only founders can reach the team page", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  const { session } = await login(env, fl.email, FREELANCER_PW);
  eq((await worker.fetch(req("/team", { cookies: { c7_session: session } }), env)).status, 404, "GET blocked");
  const post = await worker.fetch(
    req("/team", { method: "POST", cookies: { c7_session: session }, form: { name: "Sneaky", email: "sneaky@x.co", role: "founder" } }),
    env
  );
  eq(post.status, 404, "POST blocked -- a freelancer cannot mint a founder");
  eq(await db.getUserByEmail(env, "sneaky@x.co"), null, "nothing created");
});

await test("reissuing an invite invalidates the old password and link", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const fl = await seedFreelancer(env);

  const res = await worker.fetch(
    req(`/team/${fl.userId}/invite`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(res.status, 200, "status");
  const token = inviteLinkFrom(await res.text());
  assert(token, "new link issued");

  const u = await env.DB.prepare("SELECT password_hash, setup_token FROM users WHERE id = ?").bind(fl.userId).first();
  eq(u.password_hash, null, "old password cleared");
  eq(u.setup_token, token, "new token stored");

  // Their old password no longer signs them in.
  const { res: oldPw } = await login(env, fl.email, FREELANCER_PW);
  eq(oldPw.status, 401, "old password rejected");
  assert((await auditActions(env)).includes("invite_reissued"), "audited");
});

await test("revoking access ends sessions and locks the account", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const fl = await seedFreelancer(env);
  const { session: theirSession } = await login(env, fl.email, FREELANCER_PW);
  eq((await worker.fetch(req("/log", { cookies: { c7_session: theirSession } }), env)).status, 200, "they can get in beforehand");

  const res = await worker.fetch(
    req(`/team/${fl.userId}/revoke`, { method: "POST", cookies: { c7_session: theirSession ? session : session }, form: { _csrf: csrf } }),
    env
  );
  eq(res.status, 200, "status");

  const after = await env.DB.prepare(
    "SELECT password_hash, setup_token, totp_enabled FROM users WHERE id = ?"
  ).bind(fl.userId).first();
  assert(after, "the row is kept, not deleted");
  eq(after.password_hash, null, "password cleared");
  eq(after.setup_token, null, "no dangling invite");
  eq(after.totp_enabled, 0, "2FA cleared");

  const live = await worker.fetch(req("/log", { cookies: { c7_session: theirSession } }), env);
  eq(live.headers.get("Location"), "/login", "their existing session is dead immediately");
  const { res: relogin } = await login(env, fl.email, FREELANCER_PW);
  eq(relogin.status, 401, "old password no longer works");
  assert((await auditActions(env)).includes("access_revoked"), "audited");
});

await test("the lockout guards hold", async () => {
  const env = makeEnv();
  const { id, session, csrf } = await founderSession(env);

  const self = await worker.fetch(
    req(`/team/${id}/revoke`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(self.status, 400, "cannot revoke yourself");
  has(await self.text(), "revoke your own access", "explains why");

  // Add a second founder but leave them un-activated, so there is still only
  // one *working* founder login.
  await worker.fetch(
    req("/team", { method: "POST", cookies: { c7_session: session }, form: { name: "Somila", email: "somila@catalyst7.co.za", role: "founder", _csrf: csrf } }),
    env
  );
  const second = await db.getUserByEmail(env, "somila@catalyst7.co.za");
  const other = await worker.fetch(
    req(`/team/${second.id}/revoke`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  // Revoking a not-yet-activated founder is fine -- it isn't the last working login.
  eq(other.status, 200, "revoking a pending founder is allowed");

  const me = await db.getUserById(env, id);
  assert(me.has_password, "my own login is untouched throughout");
});

await test("team mutations are behind CSRF", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const fl = await seedFreelancer(env);
  for (const [p, form] of [
    ["/team", { name: "X", email: "x@y.co", role: "founder" }],
    [`/team/${fl.userId}/invite`, {}],
    [`/team/${fl.userId}/revoke`, {}],
  ]) {
    const r = await worker.fetch(req(p, { method: "POST", cookies: { c7_session: session }, form }), env);
    eq(r.status, 403, `${p} rejected without a CSRF token`);
  }
  eq(await db.getUserByEmail(env, "x@y.co"), null, "nothing created");
  const stillThere = await db.getUserById(env, fl.userId);
  assert(stillThere.has_password, "freelancer's access untouched");
});

console.log("\nJob titles");

await test("a title can be set when adding someone, and edited afterwards", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);

  await worker.fetch(
    req("/team", {
      method: "POST",
      cookies: { c7_session: session },
      form: { name: "Somila Tenza Sogaxa", email: "somila@catalyst7.co.za", role: "founder", title: "CEO / Co-Founder", _csrf: csrf },
    }),
    env
  );
  const somila = await db.getUserByEmail(env, "somila@catalyst7.co.za");
  eq(somila.title, "CEO / Co-Founder", "title stored on creation");

  const page = await (await worker.fetch(req("/team", { cookies: { c7_session: session } }), env)).text();
  has(page, "CEO / Co-Founder", "shown on the team page");

  const edit = await worker.fetch(
    req(`/team/${somila.id}/title`, { method: "POST", cookies: { c7_session: session }, form: { title: "Chief Executive", _csrf: csrf } }),
    env
  );
  eq(edit.status, 200, "edit accepted");
  eq((await db.getUserById(env, somila.id)).title, "Chief Executive", "title updated");
  assert((await auditActions(env)).includes("title_changed"), "audited");

  // Clearing it is allowed and stores NULL rather than an empty string.
  await worker.fetch(
    req(`/team/${somila.id}/title`, { method: "POST", cookies: { c7_session: session }, form: { title: "  ", _csrf: csrf } }),
    env
  );
  eq((await db.getUserById(env, somila.id)).title, null, "blank clears the title");
});

await test("a title is cosmetic — it never changes what someone can access", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const fl = await seedFreelancer(env);

  // Give a freelancer the grandest title available.
  await worker.fetch(
    req(`/team/${fl.userId}/title`, { method: "POST", cookies: { c7_session: session }, form: { title: "CEO / Co-Founder", _csrf: csrf } }),
    env
  );
  const after = await db.getUserById(env, fl.userId);
  eq(after.title, "CEO / Co-Founder", "title applied");
  eq(after.role, "freelancer", "role untouched by a title edit");

  const { session: theirs } = await login(env, fl.email, FREELANCER_PW);
  for (const p of ["/dashboard", "/team", "/revenue", "/audit"]) {
    eq((await worker.fetch(req(p, { cookies: { c7_session: theirs } }), env)).status, 404, `${p} still closed to them`);
  }
  eq((await worker.fetch(req("/log", { cookies: { c7_session: theirs } }), env)).status, 200, "their own log still works");
});

await test("titles are founder-only to edit and behind CSRF", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const fl = await seedFreelancer(env);

  const noCsrf = await worker.fetch(
    req(`/team/${fl.userId}/title`, { method: "POST", cookies: { c7_session: session }, form: { title: "Nope" } }),
    env
  );
  eq(noCsrf.status, 403, "CSRF enforced");

  const { session: theirs } = await login(env, fl.email, FREELANCER_PW);
  const theirCsrf = await csrfFor(env, theirs);
  const asFreelancer = await worker.fetch(
    req(`/team/${fl.userId}/title`, { method: "POST", cookies: { c7_session: theirs }, form: { title: "CEO", _csrf: theirCsrf } }),
    env
  );
  eq(asFreelancer.status, 404, "a freelancer cannot retitle themselves");
  eq((await db.getUserById(env, fl.userId)).title, null, "unchanged");
});

console.log("\nSelf-service registration (invite codes)");

// Mints a code the way a founder does, and returns the plaintext.
async function mintCode(env, session, csrf, form = {}) {
  const res = await worker.fetch(
    req("/team/codes", { method: "POST", cookies: { c7_session: session }, form: { role: "founder", expires_days: "7", ...form, _csrf: csrf } }),
    env
  );
  const body = await res.text();
  const m = body.match(/<span class="code-big">([A-Z0-9-]+)<\/span>/);
  return { status: res.status, code: m ? m[1] : null, body };
}

await test("the login page offers registration and /register renders", async () => {
  const env = makeEnv();
  has(await (await worker.fetch(req("/login"), env)).text(), 'href="/register"', "link on the login page");
  const reg = await worker.fetch(req("/register"), env);
  eq(reg.status, 200, "register page loads");
  const body = await reg.text();
  has(body, 'name="code"', "asks for an invite code");
  has(body, 'action="/register"', "posts to itself");
});

await test("registration is refused without a valid code", async () => {
  const env = makeEnv();
  const attempt = (code) =>
    worker.fetch(
      req("/register", {
        method: "POST",
        form: { code, name: "Intruder", email: "intruder@example.com", password: "longenough1", confirm: "longenough1" },
      }),
      env
    );

  eq((await attempt("")).status, 400, "empty code refused");
  eq((await attempt("AAAAA-BBBBB-CCCCC")).status, 403, "made-up code refused");
  eq(await db.getUserByEmail(env, "intruder@example.com"), null, "no account created");
});

await test("a founder code creates a founder, once", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const { status, code } = await mintCode(env, session, csrf, { note: "Somila" });
  eq(status, 200, "code generated");
  assert(code && /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(code), `well-formed code: ${code}`);

  const res = await worker.fetch(
    req("/register", {
      method: "POST",
      form: { code, name: "Somila Tenza Sogaxa", email: "Somila@Catalyst7.co.za", password: "her-own-password", confirm: "her-own-password" },
    }),
    env
  );
  eq(res.status, 302, "registered and signed in");
  const theirSession = setCookie(res, "c7_session");
  assert(theirSession, "session issued");

  const created = await db.getUserByEmail(env, "somila@catalyst7.co.za");
  assert(created, "email normalised to lowercase");
  eq(created.name, "Somila Tenza Sogaxa", "name stored");
  eq(created.role, "founder", "role came from the code");
  const cred = await env.DB.prepare("SELECT password_hash FROM users WHERE id = ?").bind(created.id).first();
  assert(cred.password_hash, "password set");
  lacks(cred.password_hash, "her-own-password", "plaintext never stored");

  eq((await worker.fetch(req("/dashboard", { cookies: { c7_session: theirSession } }), env)).status, 200, "founder access works");
  assert((await auditActions(env)).includes("account_registered"), "audited");

  // Second use of the same code fails.
  const reuse = await worker.fetch(
    req("/register", {
      method: "POST",
      form: { code, name: "Someone Else", email: "else@example.com", password: "longenough1", confirm: "longenough1" },
    }),
    env
  );
  eq(reuse.status, 403, "code is single-use");
  eq(await db.getUserByEmail(env, "else@example.com"), null, "no second account");
});

await test("the code decides the role — the form cannot override it", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await db.createFreelancer(env, { name: "Naledi Khumalo" });
  const fl = (await db.getFreelancers(env))[0];
  const { code } = await mintCode(env, session, csrf, { role: "freelancer", freelancer_id: String(fl.id), note: "Naledi" });
  assert(code, "freelancer code minted");

  // Submit role=founder in the form and see what actually gets created.
  const res = await worker.fetch(
    req("/register", {
      method: "POST",
      form: {
        code,
        name: "Naledi",
        email: "naledi@example.com",
        password: "longenough1",
        confirm: "longenough1",
        role: "founder",
        freelancer_id: "",
      },
    }),
    env
  );
  eq(res.status, 302, "registered");
  const created = await db.getUserByEmail(env, "naledi@example.com");
  eq(created.role, "freelancer", "privilege escalation attempt ignored");
  eq(created.freelancer_id, fl.id, "profile came from the code, not the form");

  const theirSession = setCookie(res, "c7_session");
  eq((await worker.fetch(req("/dashboard", { cookies: { c7_session: theirSession } }), env)).status, 404, "founder pages stay closed to them");
  eq((await worker.fetch(req("/log", { cookies: { c7_session: theirSession } }), env)).status, 200, "their own log works");
});

await test("registration validates its inputs and refuses duplicate emails", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const f = await env.DB.prepare("SELECT email FROM users WHERE role='founder'").first();

  const post = async (over) => {
    const { code } = await mintCode(env, session, csrf);
    return worker.fetch(
      req("/register", {
        method: "POST",
        form: { code, name: "X", email: "x@example.com", password: "longenough1", confirm: "longenough1", ...over },
      }),
      env
    );
  };

  eq((await post({ name: "" })).status, 400, "name required");
  eq((await post({ email: "nope" })).status, 400, "email must look valid");
  eq((await post({ password: "short", confirm: "short" })).status, 400, "password length enforced");
  eq((await post({ confirm: "different1" })).status, 400, "passwords must match");
  eq((await post({ email: f.email })).status, 409, "duplicate email refused");
  eq(await db.getUserByEmail(env, "x@example.com"), null, "nothing created by any of that");
});

await test("an expired or cancelled code stops working", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);

  // Expired.
  const { code: expiring } = await mintCode(env, session, csrf, { note: "old" });
  await env.DB.prepare("UPDATE invite_codes SET expires_at = datetime('now','-1 day') WHERE used_at IS NULL").run();
  const late = await worker.fetch(
    req("/register", { method: "POST", form: { code: expiring, name: "A", email: "a@example.com", password: "longenough1", confirm: "longenough1" } }),
    env
  );
  eq(late.status, 403, "expired code refused");

  // Cancelled.
  const { code: doomed } = await mintCode(env, session, csrf, { note: "cancel me" });
  const open = (await db.listInviteCodes(env)).find((c) => c.note === "cancel me");
  const cancel = await worker.fetch(
    req(`/team/codes/${open.id}/revoke`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(cancel.status, 200, "cancelled");
  const after = await worker.fetch(
    req("/register", { method: "POST", form: { code: doomed, name: "B", email: "b@example.com", password: "longenough1", confirm: "longenough1" } }),
    env
  );
  eq(after.status, 403, "cancelled code refused");
  eq(await db.getUserByEmail(env, "b@example.com"), null, "no account");
});

await test("codes are stored hashed and shown only once", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const { code } = await mintCode(env, session, csrf, { note: "Somila" });

  const { results } = await env.DB.prepare("SELECT * FROM invite_codes").all();
  eq(results.length, 1, "one code stored");
  lacks(results[0].code_hash, normalizeBackupCode(code), "plaintext code is not in the database");
  eq(results[0].created_by, (await env.DB.prepare("SELECT id FROM users").first()).id, "attributed to its creator");

  const revisit = await (await worker.fetch(req("/team", { cookies: { c7_session: session } }), env)).text();
  lacks(revisit, code, "code is not shown again on reload");
  has(revisit, "Somila", "but the note is, so you know which is which");
});

await test("only founders can mint or cancel invite codes", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  const { session } = await login(env, fl.email, FREELANCER_PW);
  eq(
    (await worker.fetch(req("/team/codes", { method: "POST", cookies: { c7_session: session }, form: { role: "founder" } }), env)).status,
    404,
    "a freelancer cannot mint a founder code"
  );
  const { results } = await env.DB.prepare("SELECT * FROM invite_codes").all();
  eq(results.length, 0, "nothing minted");
});

await test("code minting is behind CSRF", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const r = await worker.fetch(req("/team/codes", { method: "POST", cookies: { c7_session: session }, form: { role: "founder" } }), env);
  eq(r.status, 403, "rejected without a token");
  const { results } = await env.DB.prepare("SELECT * FROM invite_codes").all();
  eq(results.length, 0, "nothing minted");
});

await test("registration attempts are rate limited", async () => {
  const env = makeEnv();
  for (let i = 0; i < 5; i++) {
    const r = await worker.fetch(
      req("/register", {
        method: "POST",
        headers: { "CF-Connecting-IP": "41.13.7.9" },
        form: { code: `WRONG-CODE${i}-XXXXX`, name: "X", email: `x${i}@example.com`, password: "longenough1", confirm: "longenough1" },
      }),
      env
    );
    eq(r.status, 403, `attempt ${i + 1} refused`);
  }
  const blocked = await worker.fetch(
    req("/register", {
      method: "POST",
      headers: { "CF-Connecting-IP": "41.13.7.9" },
      form: { code: "WRONG-AGAIN-XXXXX", name: "X", email: "x9@example.com", password: "longenough1", confirm: "longenough1" },
    }),
    env
  );
  eq(blocked.status, 429, "6th attempt is rate limited, so codes can't be ground down");
});

console.log("\nC7 standard — credential hygiene, idempotency, audit fields");

await test("no credential material leaves the database except where it's verified", async () => {
  const env = makeEnv();
  const { session, id } = await founderSession(env);

  // The query that runs on EVERY authenticated request must not carry secrets.
  const req0 = req("/dashboard", { cookies: { c7_session: session } });
  const sessionUser = await (await import("../src/auth.js")).getSessionUser(req0, env);
  assert(sessionUser, "session resolves");
  eq(sessionUser.password_hash, undefined, "no password hash on the session user");
  eq(sessionUser.password_salt, undefined, "no salt either");
  eq(sessionUser.totp_secret, undefined, "no TOTP secret");
  assert(sessionUser.role && sessionUser.email, "but the fields it does need are present");

  // General-purpose lookups are credential-free too.
  const byId = await db.getUserById(env, id);
  eq(byId.password_hash, undefined, "getUserById carries no hash");
  eq(byId.has_password, 1, "it exposes a flag instead");
  const byEmail = await db.getUserByEmail(env, sessionUser.email);
  eq(byEmail.password_hash, undefined, "getUserByEmail carries no hash");

  // Exactly one function is allowed to return it, and it still works.
  const creds = await db.getUserCredentials(env, sessionUser.email);
  assert(creds.password_hash && creds.password_salt, "the login path can still verify a password");
});

await test("a double-submitted create form only creates one record", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);

  // Same nonce twice = the same form posted twice, which is what a
  // double-click produces before the first redirect lands.
  const nonce = crypto.randomUUID();
  const post = (path, form) =>
    worker.fetch(req(path, { method: "POST", cookies: { c7_session: session }, form: { ...form, _csrf: csrf, _nonce: nonce } }), env);

  const first = await post("/clients", { name: "Umlazi Foods", source: "referral" });
  eq(first.status, 302, "first submission accepted");
  const second = await post("/clients", { name: "Umlazi Foods", source: "referral" });
  eq(second.status, 302, "second submission also redirects, so the user sees no error");

  eq((await db.getClients(env)).length, 1, "but only one client exists");

  // Same again for the one where duplicates corrupt the numbers.
  const rNonce = crypto.randomUUID();
  const rev = (n) =>
    worker.fetch(
      req("/revenue", {
        method: "POST",
        cookies: { c7_session: session },
        form: { week_start: "2026-07-27", amount: "12400", type: "project", invoice_status: "paid", _csrf: csrf, _nonce: n },
      }),
      env
    );
  await rev(rNonce);
  await rev(rNonce);
  const entries = await db.getRevenueEntries(env);
  eq(entries.length, 1, "one revenue row, not two");
  eq(entries[0].amount, 12400, "and the figure is right");
});

await test("distinct submissions are unaffected by the idempotency guard", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  for (const name of ["Client A", "Client B", "Client C"]) {
    const r = await worker.fetch(
      req("/clients", { method: "POST", cookies: { c7_session: session }, form: { name, _csrf: csrf } }),
      env
    );
    eq(r.status, 302, `${name} accepted`);
  }
  eq((await db.getClients(env)).length, 3, "three separate submissions, three clients");
});

await test("every rendered form carries both a CSRF token and a fresh nonce", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const body = await (await worker.fetch(req("/clients", { cookies: { c7_session: session } }), env)).text();

  const csrfs = [...body.matchAll(/name="_csrf" value="([^"]*)"/g)].map((m) => m[1]);
  const nonces = [...body.matchAll(/name="_nonce" value="([^"]*)"/g)].map((m) => m[1]);
  assert(csrfs.length > 0, "forms are present");
  eq(nonces.length, csrfs.length, "every CSRF field is paired with a nonce");
  eq(new Set(csrfs).size, 1, "one CSRF token per session");
  eq(new Set(nonces).size, nonces.length, "but every nonce is unique");

  // A second render must produce different nonces, or replays would pass.
  const again = await (await worker.fetch(req("/clients", { cookies: { c7_session: session } }), env)).text();
  const nonces2 = [...again.matchAll(/name="_nonce" value="([^"]*)"/g)].map((m) => m[1]);
  eq(nonces.filter((n) => nonces2.includes(n)).length, 0, "no nonce is reused across renders");
});

await test("audit entries record where the action came from and whether it worked", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await worker.fetch(
    req("/clients", {
      method: "POST",
      cookies: { c7_session: session },
      headers: { "CF-Connecting-IP": "41.13.7.9" },
      form: { name: "Umlazi Foods", _csrf: csrf },
    }),
    env
  );

  const row = await env.DB.prepare("SELECT * FROM audit_log WHERE action = 'client_created'").first();
  assert(row, "the action was audited");
  eq(row.ip_address, "41.13.7.9", "IP recorded");
  eq(row.status, "success", "outcome recorded");
  assert(row.created_at, "timestamp");
  assert(row.user_id && row.user_name, "actor");
  eq(row.entity_type, "client", "target resource");

  // And the audit page still renders with the new columns.
  const page = await worker.fetch(req("/audit", { cookies: { c7_session: session } }), env);
  eq(page.status, 200, "audit page renders");
  has(await page.text(), "client_created", "showing the entry");
});

await test("blocked pages explain themselves without confirming they exist", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  const { session } = await login(env, fl.email, FREELANCER_PW);
  const res = await worker.fetch(req("/dashboard", { cookies: { c7_session: session } }), env);

  // Status stays 404: a 403 would confirm the page is real. The body explains.
  eq(res.status, 404, "status stays quiet");
  const body = await res.text();
  has(body, "isn't part of your access", "explicit restricted-access state, not a bare 'Not found'");
  has(body, 'href="/log"', "offers a way back to where they can go");
  lacks(body, "/revenue", "and doesn't enumerate the pages they can't reach");
});

await test("empty states offer a way to create the first record", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  for (const [path, cue] of [
    ["/clients", "Add your first client"],
    ["/leads", "Add your first lead"],
    ["/freelancers", "Add your first freelancer"],
    ["/revenue", "Log your first entry"],
  ]) {
    const body = await (await worker.fetch(req(path, { cookies: { c7_session: session } }), env)).text();
    has(body, cue, `${path} empty state has a creation CTA`);
    has(body, 'for="add-toggle"', `${path} CTA opens the add form`);
  }
});

console.log("\nMCP connector — discovery, OAuth, tools");

const b64u = (buf) => Buffer.from(buf).toString("base64url");
async function pkcePair() {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: b64u(new Uint8Array(digest)) };
}

// The current ISO week start, matching the app's Monday-anchored weeks.
function isoWeek() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() || 7) - 1));
  return d.toISOString().slice(0, 10);
}

async function jsonPost(env, path, body, headers = {}) {
  const res = await worker.fetch(
    new Request(ORIGIN + path, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) }),
    env
  );
  return { res, body: await res.json().catch(() => null) };
}

async function formPost(env, path, form) {
  const res = await worker.fetch(
    new Request(ORIGIN + path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form),
    }),
    env
  );
  return { res, body: await res.json().catch(() => null) };
}

// Walks the full OAuth dance the way Claude does, ending with a bearer token.
async function connectAsClaude(env, session, csrf) {
  const reg = await jsonPost(env, "/oauth/register", {
    client_name: "Claude",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  });
  const clientId = reg.body.client_id;
  const { verifier, challenge } = await pkcePair();
  const q = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "xyz",
  });
  const approve = await worker.fetch(
    req(`/oauth/authorize?${q}`, { method: "POST", cookies: { c7_session: session }, form: { decision: "allow", _csrf: csrf } }),
    env
  );
  const code = new URL(approve.headers.get("Location")).searchParams.get("code");
  const tok = await formPost(env, "/oauth/token", {
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    code_verifier: verifier,
  });
  return { clientId, verifier, challenge, ...tok.body };
}

async function rpc(env, token, method, params) {
  const res = await worker.fetch(
    new Request(ORIGIN + "/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    }),
    env
  );
  return { res, body: await res.json().catch(() => null) };
}

await test("discovery documents match what Claude expects", async () => {
  const env = makeEnv();
  const prm = await (await worker.fetch(req("/.well-known/oauth-protected-resource"), env)).json();
  eq(prm.resource, `${ORIGIN}/mcp`, "resource must equal the URL the user types into Claude");
  eq(prm.authorization_servers[0], ORIGIN, "points at our authorization server");

  // Claude probes the path-suffixed form first.
  const suffixed = await worker.fetch(req("/.well-known/oauth-protected-resource/mcp"), env);
  eq(suffixed.status, 200, "path-suffixed probe also served");

  const asm = await (await worker.fetch(req("/.well-known/oauth-authorization-server"), env)).json();
  eq(asm.issuer, ORIGIN, "issuer matches origin");
  assert(asm.registration_endpoint, "DCR advertised");
  eq(asm.code_challenge_methods_supported[0], "S256", "S256 PKCE advertised — spec requires it");
  assert(asm.token_endpoint_auth_methods_supported.includes("none"), "public client");
  assert(asm.scopes_supported.includes("mcp:read"), "scope advertised");
});

await test("an unauthenticated /mcp call returns 401 with the discovery pointer", async () => {
  const env = makeEnv();
  const { res } = await rpc(env, null, "tools/list");
  // The 401 is what starts Claude's OAuth flow. A WWW-Authenticate on a 200
  // is ignored by Claude, so the status code matters as much as the header.
  eq(res.status, 401, "401, not 200 or 403");
  const wa = res.headers.get("WWW-Authenticate");
  has(wa, "Bearer", "Bearer scheme");
  has(wa, "resource_metadata=", "points at the metadata document");
  has(wa, "/.well-known/oauth-protected-resource", "at the right path");
});

await test("the full OAuth flow issues a working token", async () => {
  const env = makeEnv();
  const { session, csrf, id } = await founderSession(env);
  const grant = await connectAsClaude(env, session, csrf);

  assert(grant.access_token, "access token issued");
  assert(grant.refresh_token, "refresh token issued");
  eq(grant.token_type, "Bearer", "bearer");
  eq(grant.scope, "mcp:read", "read-only scope");

  // Tokens are stored hashed, never in the clear.
  const stored = await env.DB.prepare("SELECT token_hash FROM mcp_tokens").all();
  eq(stored.results.length, 2, "access + refresh stored");
  for (const r of stored.results) {
    lacks(r.token_hash, grant.access_token, "raw access token not in the database");
    lacks(r.token_hash, grant.refresh_token, "raw refresh token not in the database");
  }

  const { res, body } = await rpc(env, grant.access_token, "initialize", { protocolVersion: "2025-11-25" });
  eq(res.status, 200, "initialize works");
  eq(body.result.protocolVersion, "2025-11-25", "negotiates the version Claude asked for");
  assert(body.result.capabilities.tools, "advertises tools");

  assert((await auditActions(env)).includes("mcp_access_granted"), "consent audited against the user");
  const row = await env.DB.prepare("SELECT user_id FROM mcp_tokens LIMIT 1").first();
  eq(row.user_id, id, "token is bound to the consenting user, not to the app");
});

await test("PKCE is enforced and codes are single-use", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const reg = await jsonPost(env, "/oauth/register", {
    client_name: "Claude",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  });
  const clientId = reg.body.client_id;

  const mint = async () => {
    const { verifier, challenge } = await pkcePair();
    const q = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const r = await worker.fetch(
      req(`/oauth/authorize?${q}`, { method: "POST", cookies: { c7_session: session }, form: { decision: "allow", _csrf: csrf } }),
      env
    );
    return { code: new URL(r.headers.get("Location")).searchParams.get("code"), verifier };
  };

  // Wrong verifier is rejected.
  const a = await mint();
  const bad = await formPost(env, "/oauth/token", {
    grant_type: "authorization_code",
    code: a.code,
    client_id: clientId,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    code_verifier: "not-the-verifier",
  });
  eq(bad.res.status, 400, "bad PKCE verifier rejected");
  eq(bad.body.error, "invalid_grant", "RFC 6749 error code");

  // A code is single-use even with the right verifier.
  const b = await mint();
  const first = await formPost(env, "/oauth/token", {
    grant_type: "authorization_code",
    code: b.code,
    client_id: clientId,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    code_verifier: b.verifier,
  });
  eq(first.res.status, 200, "first redemption works");
  const replay = await formPost(env, "/oauth/token", {
    grant_type: "authorization_code",
    code: b.code,
    client_id: clientId,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    code_verifier: b.verifier,
  });
  eq(replay.res.status, 400, "replayed code rejected");
});

await test("authorize refuses unregistered redirect URIs without bouncing to them", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const reg = await jsonPost(env, "/oauth/register", {
    client_name: "Claude",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  });
  const q = new URLSearchParams({
    response_type: "code",
    client_id: reg.body.client_id,
    redirect_uri: "https://evil.example.com/steal",
    code_challenge: "x".repeat(43),
    code_challenge_method: "S256",
  });
  const res = await worker.fetch(req(`/oauth/authorize?${q}`, { cookies: { c7_session: session } }), env);
  eq(res.status, 400, "refused");
  // Crucially it must NOT redirect to the attacker's URI, or this endpoint
  // becomes an open redirector.
  eq(res.headers.get("Location"), null, "does not redirect to an unregistered URI");
});

await test("refresh tokens rotate and the old one dies", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const grant = await connectAsClaude(env, session, csrf);

  const refreshed = await formPost(env, "/oauth/token", {
    grant_type: "refresh_token",
    refresh_token: grant.refresh_token,
    client_id: grant.clientId,
  });
  eq(refreshed.res.status, 200, "refresh works");
  assert(refreshed.body.access_token !== grant.access_token, "new access token");
  assert(refreshed.body.refresh_token !== grant.refresh_token, "refresh token rotated");

  const reuse = await formPost(env, "/oauth/token", {
    grant_type: "refresh_token",
    refresh_token: grant.refresh_token,
    client_id: grant.clientId,
  });
  eq(reuse.res.status, 400, "old refresh token rejected after rotation");
  eq(reuse.body.error, "invalid_grant", "the code Claude expects");
});

await test("the tools are read-only and answer with real data", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await db.createClient(env, { name: "Umlazi Foods", source: "referral" });
  await db.createLead(env, { name: "Thandi", company: "Braamfontein Bakery", stage: "qualified", value_estimate: 25000 });
  await db.createRevenueEntry(env, { week_start: isoWeek(), amount: 12400, type: "project" });
  const grant = await connectAsClaude(env, session, csrf);

  const list = await rpc(env, grant.access_token, "tools/list");
  const names = list.body.result.tools.map((t) => t.name);
  eq(names.length, 6, "six tools");
  for (const n of names) assert(!/^(add|create|update|delete|log|set)_/.test(n), `${n} must not be a write tool`);

  const summary = await rpc(env, grant.access_token, "tools/call", { name: "get_week_summary", arguments: {} });
  // en-ZA groups thousands with a non-breaking space, not a comma, so compare
  // with whitespace normalised rather than hardcoding an invisible character.
  const text = summary.body.result.content[0].text.replace(/\s/g, " ");
  has(text, "Revenue: R12 400", "real revenue figure");
  has(text, "Open pipeline: R25 000", "real pipeline figure");
  eq(summary.body.result.isError, false, "not an error");

  const leads = await rpc(env, grant.access_token, "tools/call", { name: "list_leads", arguments: { stage: "qualified" } });
  has(leads.body.result.content[0].text, "Braamfontein Bakery", "filtered leads");

  const clients = await rpc(env, grant.access_token, "tools/call", { name: "list_clients", arguments: {} });
  has(clients.body.result.content[0].text, "Umlazi Foods", "clients");

  // Data is unchanged by any of it.
  eq((await db.getClients(env)).length, 1, "no writes happened");
  eq((await db.getLeads(env)).length, 1, "no writes happened");
});

await test("a freelancer's token cannot read founder data", async () => {
  const env = makeEnv();
  const fl = await seedFreelancer(env);
  await db.createClient(env, { name: "Secret Client" });
  await db.upsertWeeklyEntry(env, { week_start: isoWeek(), freelancer_id: fl.freelancerId, hours: 21, deliverables: "Brand board" });

  const { session } = await login(env, fl.email, FREELANCER_PW);
  const csrf = await csrfFor(env, session);
  const grant = await connectAsClaude(env, session, csrf);

  for (const tool of ["get_week_summary", "list_leads", "list_clients", "list_revenue", "list_freelancers"]) {
    const r = await rpc(env, grant.access_token, "tools/call", { name: tool, arguments: {} });
    has(r.body.result.content[0].text, "only available to founders", `${tool} refused`);
    lacks(r.body.result.content[0].text, "Secret Client", `${tool} leaks nothing`);
  }

  // But their own log works.
  const own = await rpc(env, grant.access_token, "tools/call", { name: "get_my_weekly_log", arguments: {} });
  has(own.body.result.content[0].text, "Brand board", "their own entries are readable");
});

await test("revoking someone's HQ access kills their connector too", async () => {
  const env = makeEnv();
  const founder = await founderSession(env);
  const fl = await seedFreelancer(env);
  const { session: theirs } = await login(env, fl.email, FREELANCER_PW);
  const grant = await connectAsClaude(env, theirs, await csrfFor(env, theirs));

  eq((await rpc(env, grant.access_token, "tools/list")).res.status, 200, "connector works beforehand");

  await worker.fetch(
    req(`/team/${fl.userId}/revoke`, { method: "POST", cookies: { c7_session: founder.session }, form: { _csrf: founder.csrf } }),
    env
  );

  const after = await rpc(env, grant.access_token, "tools/list");
  eq(after.res.status, 401, "connector is dead the moment access is revoked");
});

await test("a user can disconnect a connector from Security", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const grant = await connectAsClaude(env, session, csrf);
  eq((await rpc(env, grant.access_token, "tools/list")).res.status, 200, "working");

  const page = await (await worker.fetch(req("/security", { cookies: { c7_session: session } }), env)).text();
  has(page, "Connected apps", "listed on the Security page");
  has(page, "Claude", "by name");

  await worker.fetch(
    req("/security/connectors/revoke", { method: "POST", cookies: { c7_session: session }, form: { client_id: grant.clientId, _csrf: csrf } }),
    env
  );
  eq((await rpc(env, grant.access_token, "tools/list")).res.status, 401, "disconnected");
  assert((await auditActions(env)).includes("mcp_access_revoked"), "audited");
});

await test("the MCP endpoint rejects what it should", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  const grant = await connectAsClaude(env, session, csrf);

  // No standalone SSE stream and no sessions in this revision.
  eq((await worker.fetch(req("/mcp"), env)).status, 405, "GET not allowed");

  // DNS-rebinding guard.
  const crossOrigin = await worker.fetch(
    new Request(ORIGIN + "/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example.com", Authorization: `Bearer ${grant.access_token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
    env
  );
  eq(crossOrigin.status, 403, "cross-origin browser request refused");

  eq((await rpc(env, "made-up-token", "tools/list")).res.status, 401, "forged token refused");
  const unknown = await rpc(env, grant.access_token, "does/not/exist");
  eq(unknown.res.status, 404, "unknown method → 404");
  eq(unknown.body.error.code, -32601, "with the JSON-RPC method-not-found code");
});

console.log("\nOutreach webhook from Make (CRM step 1)");

const MAKE_SECRET = "shared-secret-for-tests";

function makeEnvWithWebhook() {
  const env = makeEnv();
  env.MAKE_WEBHOOK_SECRET = MAKE_SECRET;
  return env;
}

async function signBody(secret, raw) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(raw));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Posts a C7-envelope event the way Make would.
async function postEvent(env, data, { secret = MAKE_SECRET, eventId, timestamp, sign = true } = {}) {
  const payload = {
    event_id: eventId || `evt_${crypto.randomUUID()}`,
    timestamp: timestamp || new Date().toISOString(),
    source: "make_outreach",
    form_name: "outreach_event_v1",
    data,
  };
  const raw = JSON.stringify(payload);
  const headers = { "Content-Type": "application/json" };
  if (sign) headers["X-Signature-256"] = "sha256=" + (await signBody(secret, raw));
  const res = await worker.fetch(new Request(ORIGIN + "/webhooks/make", { method: "POST", headers, body: raw }), env);
  return { res, body: await res.json().catch(() => null), payload };
}

await test("the webhook stays dormant until a secret is configured", async () => {
  const env = makeEnv(); // no MAKE_WEBHOOK_SECRET
  const { res } = await postEvent(env, { kind: "sent", email: "x@y.co" });
  eq(res.status, 404, "endpoint not exposed without a secret");
});

await test("an unsigned or wrongly signed event is refused", async () => {
  const env = makeEnvWithWebhook();
  const unsigned = await postEvent(env, { kind: "sent", email: "x@y.co" }, { sign: false });
  eq(unsigned.res.status, 401, "unsigned refused");

  const wrong = await postEvent(env, { kind: "sent", email: "x@y.co" }, { secret: "not-the-secret" });
  eq(wrong.res.status, 401, "wrong secret refused");

  const { results } = await env.DB.prepare("SELECT * FROM outreach_events").all();
  eq(results.length, 0, "nothing recorded from an unauthenticated caller");
  assert((await auditActions(env)).includes("webhook_rejected"), "rejection is audited");
});

await test("a signed event is recorded and matched to its lead", async () => {
  const env = makeEnvWithWebhook();
  await db.createLead(env, { name: "Thandi Mokoena", company: "Braamfontein Bakery", contact_email: "Thandi@Bakery.co.za" });
  const lead = (await db.getLeads(env))[0];

  const { res, body } = await postEvent(env, {
    kind: "sent",
    email: "thandi@bakery.co.za", // different case from the lead record
    sequence: "cold_outreach_v2",
    step: 1,
    subject: "Quick question about Braamfontein Bakery",
  });
  eq(res.status, 200, "accepted");
  eq(body.success, true, "C7 standard response shape");
  eq(body.matched_lead, lead.id, "matched to the lead despite differing case");

  const events = await db.getOutreachForLead(env, lead.id);
  eq(events.length, 1, "one event on the timeline");
  eq(events[0].kind, "sent", "kind recorded");
  eq(events[0].sequence, "cold_outreach_v2", "sequence recorded");
  eq(events[0].subject, "Quick question about Braamfontein Bakery", "subject recorded");
});

await test("a retried event lands once, not twice", async () => {
  const env = makeEnvWithWebhook();
  await db.createLead(env, { name: "Thandi", contact_email: "t@b.co.za" });
  const id = "evt_fixed_for_retry";

  const first = await postEvent(env, { kind: "sent", email: "t@b.co.za", subject: "Hello" }, { eventId: id });
  const second = await postEvent(env, { kind: "sent", email: "t@b.co.za", subject: "Hello" }, { eventId: id });

  eq(first.res.status, 200, "first accepted");
  // A duplicate must still be a success, or Make retries forever.
  eq(second.res.status, 200, "retry also answers 200");
  has(second.body.message, "already recorded", "but says it was a duplicate");

  const { results } = await env.DB.prepare("SELECT * FROM outreach_events").all();
  eq(results.length, 1, "recorded exactly once");
});

await test("replies and bounces are recorded, and unknown kinds refused", async () => {
  const env = makeEnvWithWebhook();
  await db.createLead(env, { name: "Thandi", contact_email: "t@b.co.za" });
  const lead = (await db.getLeads(env))[0];

  await postEvent(env, { kind: "reply", email: "t@b.co.za", detail: "Sounds interesting, call me Thursday" });
  await postEvent(env, { kind: "bounce", email: "t@b.co.za", detail: "550 mailbox unavailable" });
  const bad = await postEvent(env, { kind: "opened", email: "t@b.co.za" });
  eq(bad.res.status, 400, "an unsupported kind is refused rather than stored as junk");

  const events = await db.getOutreachForLead(env, lead.id);
  eq(events.length, 2, "reply and bounce stored");
  assert(events.some((e) => e.kind === "reply"), "reply");
  assert(events.some((e) => e.kind === "bounce"), "bounce");
});

await test("a send to an address with no matching lead is kept, not dropped", async () => {
  const env = makeEnvWithWebhook();
  const { res, body } = await postEvent(env, { kind: "sent", email: "nobody@example.com", subject: "Hi" });
  eq(res.status, 200, "accepted");
  eq(body.matched_lead, null, "no lead matched");
  const orphans = await db.getUnmatchedOutreach(env);
  eq(orphans.length, 1, "still visible rather than silently discarded");
  eq(orphans[0].lead_email, "nobody@example.com", "with the address it went to");
});

await test("stale and malformed timestamps are refused", async () => {
  const env = makeEnvWithWebhook();
  const old = await postEvent(env, { kind: "sent", email: "a@b.co" }, { timestamp: new Date(Date.now() - 30 * 86400000).toISOString() });
  eq(old.res.status, 400, "a month-old capture is refused");
  const junk = await postEvent(env, { kind: "sent", email: "a@b.co" }, { timestamp: "not-a-date" });
  eq(junk.res.status, 400, "malformed timestamp refused");
  const future = await postEvent(env, { kind: "sent", email: "a@b.co" }, { timestamp: new Date(Date.now() + 3600000).toISOString() });
  eq(future.res.status, 400, "a timestamp an hour in the future is refused");
});

await test("the lead page shows its outreach timeline", async () => {
  const env = makeEnvWithWebhook();
  const { session } = await founderSession(env);
  await db.createLead(env, { name: "Thandi Mokoena", company: "Braamfontein Bakery", contact_email: "t@b.co.za" });
  const lead = (await db.getLeads(env))[0];
  await postEvent(env, { kind: "sent", email: "t@b.co.za", sequence: "cold_v2", step: 1, subject: "Quick question" });
  await postEvent(env, { kind: "reply", email: "t@b.co.za", detail: "Interested" });

  const page = await worker.fetch(req(`/leads/${lead.id}`, { cookies: { c7_session: session } }), env);
  eq(page.status, 200, "lead page renders");
  const body = await page.text();
  has(body, "Quick question", "the sent email");
  has(body, "cold_v2", "the sequence name");
  has(body, "Interested", "the reply");
  has(body, "Outreach activity", "timeline panel");

  // And the list view summarises it.
  const list = await (await worker.fetch(req("/leads", { cookies: { c7_session: session } }), env)).text();
  has(list, `href="/leads/${lead.id}"`, "list links through to the lead");
  has(list, "1 sent, 1 replied", "outreach summarised in the table");
});

await test("lead pages are founder-only and reject unknown ids", async () => {
  const env = makeEnvWithWebhook();
  await db.createLead(env, { name: "Thandi", contact_email: "t@b.co.za" });
  const lead = (await db.getLeads(env))[0];
  const fl = await seedFreelancer(env);
  const { session } = await login(env, fl.email, FREELANCER_PW);
  eq((await worker.fetch(req(`/leads/${lead.id}`, { cookies: { c7_session: session } }), env)).status, 404, "freelancer blocked");

  const founder = await founderSession(env);
  eq(
    (await worker.fetch(req("/leads/99999", { cookies: { c7_session: founder.session } }), env)).status,
    404,
    "unknown lead id"
  );
});

console.log("\nOutreach approval + send trigger (CRM step 2)");

// Stubs the Make endpoint so no real scenario fires during tests.
function stubMakeEndpoint({ status = 200, body = "Accepted", hang = false } = {}) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init) => {
    if (String(input).includes("hook.eu2.make.com")) {
      calls.push({ url: String(input), headers: init?.headers || {}, body: init?.body });
      if (hang) await new Promise((r) => setTimeout(r, 50_000));
      return new Response(body, { status });
    }
    return original(input, init);
  };
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

function sendingEnv() {
  const env = makeEnv();
  env.MAKE_WEBHOOK_SECRET = "shared-secret-for-tests";
  env.MAKE_OUTREACH_URL = "https://hook.eu2.make.com/abc123";
  return env;
}

async function seedLead(env, over = {}) {
  await db.createLead(env, {
    name: "Thandi Mokoena",
    company: "Braamfontein Bakery",
    contact_email: "thandi@bakery.co.za",
    stage: "qualified",
    ...over,
  });
  // Highest id, not getLeads()[0]: getLeads orders by updated_at, which has
  // second resolution, so with several leads seeded in one test the "first" row
  // is whichever the tie broke toward -- and every later assertion would be
  // pointed at the wrong lead.
  const all = await db.getLeads(env);
  return all.reduce((newest, l) => (l.id > newest.id ? l : newest), all[0]);
}

await test("a new lead starts unapproved and appears in the queue", async () => {
  const env = sendingEnv();
  const { session } = await founderSession(env);
  const lead = await seedLead(env);
  eq(lead.outreach_status, "pending", "pending by default — nothing is pre-authorised");

  const page = await (await worker.fetch(req("/outreach", { cookies: { c7_session: session } }), env)).text();
  has(page, "Thandi Mokoena", "shows in the approval queue");
  has(page, "Awaiting approval", "queue panel");
});

await test("approving records who decided, and rejecting removes it from the queue", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env);

  await worker.fetch(
    req(`/leads/${lead.id}/outreach/approve`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  let after = await db.getLeadById(env, lead.id);
  eq(after.outreach_status, "approved", "approved");
  assert(after.outreach_approved_by, "records who approved it, not just that it happened");
  assert(after.outreach_approved_at, "and when");
  assert((await auditActions(env)).includes("outreach_approved"), "audited");

  await worker.fetch(
    req(`/leads/${lead.id}/outreach/reject`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  after = await db.getLeadById(env, lead.id);
  eq(after.outreach_status, "rejected", "rejected");
  eq(after.outreach_approved_by, null, "approval attribution cleared on reject");
  eq((await db.getLeadsAwaitingApproval(env)).length, 0, "gone from the queue");
});

await test("a lead with no email cannot be approved", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env, { contact_email: null });
  const res = await worker.fetch(
    req(`/leads/${lead.id}/outreach/approve`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(res.status, 400, "refused");
  eq((await db.getLeadById(env, lead.id)).outreach_status, "pending", "still pending");
});

await test("an approved lead triggers Make with a signed C7 envelope", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env);
  await db.setOutreachStatus(env, lead.id, "approved", "Somila");

  const stub = stubMakeEndpoint({ status: 200, body: "Accepted" });
  try {
    const res = await worker.fetch(
      req(`/leads/${lead.id}/outreach/send`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
      env
    );
    eq(res.status, 302, "redirects back to the lead");
    eq(stub.calls.length, 1, "Make was called exactly once");

    const call = stub.calls[0];
    const sig = call.headers["X-Signature-256"] || call.headers["x-signature-256"];
    assert(sig && sig.startsWith("sha256="), "signed with the shared secret");

    const sent = JSON.parse(call.body);
    eq(sent.source, "catalyst7_hq", "identifies HQ as the caller");
    eq(sent.form_name, "outreach_send_v1", "C7 envelope");
    assert(sent.event_id && sent.timestamp, "envelope fields present");
    eq(sent.data.email, "thandi@bakery.co.za", "the lead's address");
    eq(sent.data.first_name, "Thandi", "first name split out for the email template");
    eq(sent.data.company, "Braamfontein Bakery", "company for merge fields");

    // The send is recorded against the lead using the same event_id Make saw.
    const events = await db.getOutreachForLead(env, lead.id);
    eq(events.length, 1, "one event recorded");
    eq(events[0].kind, "sent", "recorded as sent");
    eq(events[0].sequence, "hq_manual", "marked as an HQ-triggered send");
    assert((await db.getLeadById(env, lead.id)).outreach_last_sent_at, "last-sent stamped on the lead");
    assert((await auditActions(env)).includes("outreach_sent"), "audited");
  } finally {
    stub.restore();
  }
});

await test("an unapproved lead cannot be sent to, even by forging the request", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env); // still pending

  const stub = stubMakeEndpoint();
  try {
    const res = await worker.fetch(
      req(`/leads/${lead.id}/outreach/send`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
      env
    );
    eq(res.status, 400, "refused");
    eq(stub.calls.length, 0, "Make was never called");
    eq((await db.getOutreachForLead(env, lead.id)).length, 0, "nothing recorded");
  } finally {
    stub.restore();
  }
});

await test("a failing Make is recorded on the lead, not swallowed", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env);
  await db.setOutreachStatus(env, lead.id, "approved", "Somila");

  const stub = stubMakeEndpoint({ status: 500, body: "Scenario failed" });
  try {
    await worker.fetch(
      req(`/leads/${lead.id}/outreach/send`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
      env
    );
    const events = await db.getOutreachForLead(env, lead.id);
    eq(events.length, 1, "the attempt is still recorded");
    eq(events[0].kind, "failed", "as a failure, so it's visible on the lead");
    has(events[0].detail, "500", "with what Make actually returned");
    eq((await db.getLeadById(env, lead.id)).outreach_last_sent_at, null, "not marked as sent");
    assert((await auditActions(env)).includes("outreach_send_failed"), "audited as a failure");
  } finally {
    stub.restore();
  }
});

await test("double-clicking Send only sends once", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env);
  await db.setOutreachStatus(env, lead.id, "approved", "Somila");

  const stub = stubMakeEndpoint();
  try {
    const nonce = crypto.randomUUID();
    const send = () =>
      worker.fetch(
        req(`/leads/${lead.id}/outreach/send`, {
          method: "POST",
          cookies: { c7_session: session },
          form: { _csrf: csrf, _nonce: nonce },
        }),
        env
      );
    await send();
    await send();
    eq(stub.calls.length, 1, "Make called once, not twice — an email can't be unsent");
    eq((await db.getOutreachForLead(env, lead.id)).length, 1, "one event");
  } finally {
    stub.restore();
  }
});

await test("sending is refused entirely when it isn't configured", async () => {
  const env = makeEnv(); // no MAKE_OUTREACH_URL
  const { session, csrf } = await founderSession(env);
  const lead = await seedLead(env);
  await db.setOutreachStatus(env, lead.id, "approved", "Somila");

  const res = await worker.fetch(
    req(`/leads/${lead.id}/outreach/send`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );
  eq(res.status, 400, "refused rather than half-attempted");
  eq((await db.getOutreachForLead(env, lead.id)).length, 0, "nothing recorded");
});

await test("the outreach page and its actions are founder-only and CSRF-guarded", async () => {
  const env = sendingEnv();
  const { session } = await founderSession(env);
  const lead = await seedLead(env);

  const noCsrf = await worker.fetch(
    req(`/leads/${lead.id}/outreach/approve`, { method: "POST", cookies: { c7_session: session } }),
    env
  );
  eq(noCsrf.status, 403, "approval needs a CSRF token");
  eq((await db.getLeadById(env, lead.id)).outreach_status, "pending", "unchanged");

  const fl = await seedFreelancer(env);
  const { session: theirs } = await login(env, fl.email, FREELANCER_PW);
  eq((await worker.fetch(req("/outreach", { cookies: { c7_session: theirs } }), env)).status, 404, "queue is founder-only");
  const theirCsrf = await csrfFor(env, theirs);
  const attempt = await worker.fetch(
    req(`/leads/${lead.id}/outreach/approve`, { method: "POST", cookies: { c7_session: theirs }, form: { _csrf: theirCsrf } }),
    env
  );
  eq(attempt.status, 404, "a freelancer cannot approve outreach");
  eq((await db.getLeadById(env, lead.id)).outreach_status, "pending", "still unchanged");
});

console.log("\nCall window & outcome log (CRM step 3)");

// Sequence B: send, wait a short window, then call REGARDLESS of whether they
// replied, then log the outcome. The decision log calls this the sequence's one
// unbuilt dependency, so these tests care most about two things: that a window
// only ever opens off a real send, and that the queue never quietly drops the
// leads who replied.

// Takes the caller's session rather than minting its own: founderSession seeds
// a user, and a second one would collide on the unique email.
async function sentLead(env, auth, over = {}) {
  const seeded = await seedLead(env, over);
  await db.setOutreachStatus(env, seeded.id, "approved", "Somila");
  const stub = stubMakeEndpoint();
  try {
    await worker.fetch(
      req(`/leads/${seeded.id}/outreach/send`, {
        method: "POST",
        cookies: { c7_session: auth.session },
        form: { _csrf: auth.csrf },
      }),
      env
    );
  } finally {
    stub.restore();
  }
  return db.getLeadById(env, seeded.id);
}

function hoursUntil(sqlUtc) {
  return (Date.parse(String(sqlUtc).replace(" ", "T") + "Z") - Date.now()) / 3_600_000;
}

await test("a successful send opens the call window", async () => {
  const env = sendingEnv();
  const lead = await sentLead(env, await founderSession(env));
  assert(lead.call_due_at, "the window is stamped on the lead, not left to a human to remember");
  eq(lead.call_outcome, null, "no outcome yet");

  const gap = hoursUntil(lead.call_due_at);
  assert(gap > 17 && gap < 19, `default window is ~18h, got ${gap.toFixed(1)}h`);
});

await test("CALL_WINDOW_HOURS moves the window, and nonsense values cannot break it", async () => {
  const env = sendingEnv();
  env.CALL_WINDOW_HOURS = "4";
  const lead = await sentLead(env, await founderSession(env));
  const gap = hoursUntil(lead.call_due_at);
  assert(gap > 3 && gap < 5, `respects the override, got ${gap.toFixed(1)}h`);

  eq(callWindowHours({ CALL_WINDOW_HOURS: "0" }), 1, "zero would make every lead due instantly - clamped");
  eq(callWindowHours({ CALL_WINDOW_HOURS: "-5" }), 1, "negative clamped");
  eq(callWindowHours({ CALL_WINDOW_HOURS: "99999" }), 168, "absurd values would hide the queue forever - clamped");
  eq(callWindowHours({ CALL_WINDOW_HOURS: "banana" }), 18, "unparseable falls back to the default");
  eq(callWindowHours({}), 18, "unset falls back to the default");
});

await test("a FAILED send opens no window", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const seeded = await seedLead(env);
  await db.setOutreachStatus(env, seeded.id, "approved", "Somila");

  const stub = stubMakeEndpoint({ status: 500, body: "Scenario failed" });
  try {
    await worker.fetch(
      req(`/leads/${seeded.id}/outreach/send`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
      env
    );
  } finally {
    stub.restore();
  }
  const after = await db.getLeadById(env, seeded.id);
  eq(after.call_due_at, null, "no email arrived, so calling would be a cold call, not sequence B");
  const counts = await db.countCallQueue(env);
  eq(counts.due + counts.waiting, 0, "and it stays out of the queue");
});

await test("the queue keeps leads who already replied - that is the point of sequence B", async () => {
  const env = sendingEnv();
  env.CALL_WINDOW_HOURS = "1";
  const auth = await founderSession(env);
  const { session } = auth;
  const lead = await sentLead(env, auth);

  await db.recordOutreachEvent(env, {
    event_id: "evt_reply_1",
    lead_id: lead.id,
    lead_email: lead.contact_email,
    kind: "reply",
    occurred_at: new Date().toISOString(),
    source: "make_outreach",
  });

  const queue = await db.getCallQueue(env);
  eq(queue.length, 1, "still queued after replying - filtering repliers out would bias the outcome data");
  assert(queue[0].replied_since_send, "but the caller is told they replied");

  const page = await (await worker.fetch(req("/calls", { cookies: { c7_session: session } }), env)).text();
  has(page, "Thandi Mokoena", "shown on the calls page");
  has(page, "call anyway", "and the page says so out loud");
});

await test("logging an outcome closes the window and lands on the timeline", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await sentLead(env, { session, csrf });

  const res = await worker.fetch(
    req(`/leads/${lead.id}/call/log`, {
      method: "POST",
      cookies: { c7_session: session },
      form: { _csrf: csrf, outcome: "picked_up_cold", notes: "Wants the audit emailed over." },
    }),
    env
  );
  eq(res.status, 302, "redirects back");

  const after = await db.getLeadById(env, lead.id);
  eq(after.call_outcome, "picked_up_cold", "outcome recorded");
  assert(after.call_logged_at, "and when");
  assert(after.call_logged_by, "and by whom, not by 'the system'");

  const events = await db.getOutreachForLead(env, lead.id);
  const call = events.find((e) => e.kind === "call");
  assert(call, "the call is on the ledger, not only in a lead column");
  eq(call.subject, "Picked up cold", "with the same wording the queue showed");
  has(call.detail, "audit emailed over", "notes kept");
  eq(call.sequence, "sequence_b", "attributed to the sequence it belongs to");

  eq((await db.getCallQueue(env)).length, 0, "gone from the queue");
  assert((await auditActions(env)).includes("call_logged"), "audited");
});

await test("an outcome outside the agreed set is refused", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await sentLead(env, { session, csrf });

  for (const outcome of ["", "maybe", "DROP TABLE leads", "picked_up"]) {
    const res = await worker.fetch(
      req(`/leads/${lead.id}/call/log`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf, outcome } }),
      env
    );
    eq(res.status, 400, `refused: ${outcome || "(empty)"}`);
  }
  eq((await db.getLeadById(env, lead.id)).call_outcome, null, "nothing written");
  eq((await db.getOutreachForLead(env, lead.id)).filter((e) => e.kind === "call").length, 0, "no phantom call events");
});

await test("a call cannot be logged against a lead nothing was sent to", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const seeded = await seedLead(env); // never sent to

  const res = await worker.fetch(
    req(`/leads/${seeded.id}/call/log`, {
      method: "POST",
      cookies: { c7_session: session },
      form: { _csrf: csrf, outcome: "no_response" },
    }),
    env
  );
  eq(res.status, 400, "refused - the stats only mean something across leads that went through the sequence");
  eq((await db.getLeadById(env, seeded.id)).call_outcome, null, "unchanged");
});

await test("double-submitting the log form records one call", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await sentLead(env, { session, csrf });

  const nonce = crypto.randomUUID();
  const submit = () =>
    worker.fetch(
      req(`/leads/${lead.id}/call/log`, {
        method: "POST",
        cookies: { c7_session: session },
        form: { _csrf: csrf, _nonce: nonce, outcome: "no_response" },
      }),
      env
    );
  await submit();
  await submit();
  eq(
    (await db.getOutreachForLead(env, lead.id)).filter((e) => e.kind === "call").length,
    1,
    "one call on the timeline, not two"
  );
});

await test("reopening clears the outcome but never erases the logged call", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await sentLead(env, { session, csrf });

  await worker.fetch(
    req(`/leads/${lead.id}/call/log`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf, outcome: "skipped" } }),
    env
  );
  await worker.fetch(
    req(`/leads/${lead.id}/call/reopen`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
    env
  );

  const after = await db.getLeadById(env, lead.id);
  eq(after.call_outcome, null, "back in the queue");
  assert(after.call_due_at, "the original window is kept - a correction is not a new send");
  eq(
    (await db.getOutreachForLead(env, lead.id)).filter((e) => e.kind === "call").length,
    1,
    "the ledger still says a call was logged - a correction does not get to rewrite what was done"
  );
  assert((await auditActions(env)).includes("call_reopened"), "audited");
});

await test("skipped calls are counted but kept out of the comparable set", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  for (const outcome of ["picked_up_cold", "replied_first", "no_response", "skipped"]) {
    const lead = await sentLead(env, { session, csrf }, { contact_email: `${outcome}@bakery.co.za`, name: `Lead ${outcome}` });
    await worker.fetch(
      req(`/leads/${lead.id}/call/log`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf, outcome } }),
      env
    );
  }
  const stats = await db.getCallOutcomeStats(env);
  eq(stats.skipped, 1, "skipped is still counted");
  eq(stats.comparable, 3, "but a call that never happened says nothing about whether calling works");

  const page = await (await worker.fetch(req("/calls", { cookies: { c7_session: session } }), env)).text();
  has(page, "3 comparable calls", "the page says which number is the comparable one");
  has(page, "1 skipped and excluded", "and is explicit that skipped is excluded");
});

await test("a re-send opens a fresh window and drops the previous outcome", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const lead = await sentLead(env, { session, csrf });
  await worker.fetch(
    req(`/leads/${lead.id}/call/log`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf, outcome: "no_response" } }),
    env
  );

  const stub = stubMakeEndpoint();
  try {
    await worker.fetch(
      req(`/leads/${lead.id}/outreach/send`, { method: "POST", cookies: { c7_session: session }, form: { _csrf: csrf } }),
      env
    );
  } finally {
    stub.restore();
  }
  const after = await db.getLeadById(env, lead.id);
  eq(after.call_outcome, null, "the old outcome would otherwise be read as the new call's result");
  eq((await db.getCallQueue(env)).length, 1, "back in the queue for the new send");
  eq(
    (await db.getOutreachForLead(env, lead.id)).filter((e) => e.kind === "call").length,
    1,
    "the first call is still in the history"
  );
});

await test("the calls page and its actions are founder-only and CSRF-guarded", async () => {
  const env = sendingEnv();
  const auth = await founderSession(env);
  const { session } = auth;
  const lead = await sentLead(env, auth);

  const noCsrf = await worker.fetch(
    req(`/leads/${lead.id}/call/log`, { method: "POST", cookies: { c7_session: session }, form: { outcome: "no_response" } }),
    env
  );
  eq(noCsrf.status, 403, "logging needs a CSRF token");
  eq((await db.getLeadById(env, lead.id)).call_outcome, null, "unchanged");

  const fl = await seedFreelancer(env);
  const { session: theirs } = await login(env, fl.email, FREELANCER_PW);
  eq((await worker.fetch(req("/calls", { cookies: { c7_session: theirs } }), env)).status, 404, "calls page is founder-only");
  const theirCsrf = await csrfFor(env, theirs);
  const attempt = await worker.fetch(
    req(`/leads/${lead.id}/call/log`, {
      method: "POST",
      cookies: { c7_session: theirs },
      form: { _csrf: theirCsrf, outcome: "picked_up_cold" },
    }),
    env
  );
  eq(attempt.status, 404, "a freelancer cannot log a call");
  eq((await db.getLeadById(env, lead.id)).call_outcome, null, "still unchanged");
});


// A send Make made itself must still open the window. Most of the Apify
// pipeline's email is sent by the scenario, not by HQ, so without this the
// queue would sit empty while outreach went out.

async function postSent(env, { email, at, eventId = `evt_${crypto.randomUUID()}`, kind = "sent" }) {
  const payload = {
    event_id: eventId,
    timestamp: at || new Date().toISOString(),
    source: "make_outreach",
    form_name: "outreach_event_v1",
    data: { kind, email, sequence: "cold_outreach_v2", step: 1, subject: "Quick question" },
  };
  const body = JSON.stringify(payload);
  const sig = await signBody(env.MAKE_WEBHOOK_SECRET, body);
  return worker.fetch(
    new Request("https://hq.test/webhooks/make", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature-256": `sha256=${sig}` },
      body,
    }),
    env
  );
}

await test("a send reported by Make opens the call window too", async () => {
  const env = sendingEnv();
  const seeded = await seedLead(env);
  eq(seeded.call_due_at, null, "no window before the send");

  const res = await postSent(env, { email: "thandi@bakery.co.za" });
  eq(res.status, 200, "webhook accepted");

  const after = await db.getLeadById(env, seeded.id);
  assert(after.call_due_at, "Make sent it, so the call is still due - the queue must not sit empty while outreach goes out");
  eq((await db.getCallQueue(env)).length, 1, "and it is in the queue");
  assert((await auditActions(env)).includes("call_window_opened"), "audited");
});

await test("the window is dated off the event, not off when the webhook arrived", async () => {
  const env = sendingEnv();
  const seeded = await seedLead(env);

  // Make fires late: the email went out 6 hours ago.
  const sixHoursAgo = new Date(Date.now() - 6 * 3_600_000).toISOString();
  await postSent(env, { email: "thandi@bakery.co.za", at: sixHoursAgo });

  const after = await db.getLeadById(env, seeded.id);
  const gap = (Date.parse(String(after.call_due_at).replace(" ", "T") + "Z") - Date.now()) / 3_600_000;
  assert(gap > 11 && gap < 13, `18h from the send, i.e. ~12h from now, got ${gap.toFixed(1)}h`);
});

await test("a replayed webhook cannot reset the window or discard a logged call", async () => {
  const env = sendingEnv();
  const { session, csrf } = await founderSession(env);
  const seeded = await seedLead(env);

  const eventId = "evt_stable_1";
  await postSent(env, { email: "thandi@bakery.co.za", eventId });
  await worker.fetch(
    req(`/leads/${seeded.id}/call/log`, {
      method: "POST",
      cookies: { c7_session: session },
      form: { _csrf: csrf, outcome: "no_response" },
    }),
    env
  );

  // Make retries the same event.
  const res = await postSent(env, { email: "thandi@bakery.co.za", eventId });
  eq(res.status, 200, "retry still succeeds, or Make would retry forever");

  const after = await db.getLeadById(env, seeded.id);
  eq(after.call_outcome, "no_response", "the logged call survives the replay");
  eq((await db.getCallQueue(env)).length, 0, "and it does not reappear in the queue");
});

await test("an out-of-order older send cannot roll a newer window back", async () => {
  const env = sendingEnv();
  const seeded = await seedLead(env);

  await postSent(env, { email: "thandi@bakery.co.za", at: new Date().toISOString(), eventId: "evt_new" });
  const newWindow = (await db.getLeadById(env, seeded.id)).call_due_at;

  // A much older send event turns up afterwards.
  const twoDaysAgo = new Date(Date.now() - 48 * 3_600_000).toISOString();
  await postSent(env, { email: "thandi@bakery.co.za", at: twoDaysAgo, eventId: "evt_old" });

  eq((await db.getLeadById(env, seeded.id)).call_due_at, newWindow, "the newer window stands");
});

await test("an out-of-order send on the SAME DAY cannot roll the window back", async () => {
  const env = sendingEnv();
  const seeded = await seedLead(env);

  // Both on yesterday's UTC date, so the day part is identical and only the
  // time separates them. This is the case that catches an unnormalised
  // comparison: raw ISO puts "T" where the stored format has a space, and "T"
  // sorts after " ", so an older same-day event would look newer than
  // everything and sail through the forward-only guard.
  const day = new Date(Date.now() - 24 * 3_600_000).toISOString().slice(0, 10);
  const later = `${day}T12:00:00.000Z`;
  const earlier = `${day}T09:00:00.000Z`;

  await postSent(env, { email: "thandi@bakery.co.za", at: later, eventId: "evt_late" });
  const window = (await db.getLeadById(env, seeded.id)).call_due_at;

  await postSent(env, { email: "thandi@bakery.co.za", at: earlier, eventId: "evt_early" });
  eq((await db.getLeadById(env, seeded.id)).call_due_at, window, "the 12:00 send still owns the window, not the 09:00 one");
});

await test("replies and bounces do not open a call window", async () => {
  const env = sendingEnv();
  const seeded = await seedLead(env);

  await postSent(env, { email: "thandi@bakery.co.za", kind: "reply", eventId: "evt_r" });
  await postSent(env, { email: "thandi@bakery.co.za", kind: "bounce", eventId: "evt_b" });

  const after = await db.getLeadById(env, seeded.id);
  eq(after.call_due_at, null, "nothing was sent, so there is nothing to follow up");
  eq((await db.getCallQueue(env)).length, 0, "queue stays empty");
});

await test("a send to an address with no lead opens no window and still records", async () => {
  const env = sendingEnv();
  await seedLead(env);
  const res = await postSent(env, { email: "nobody@nowhere.test" });
  eq(res.status, 200, "still accepted");
  eq((await db.getCallQueue(env)).length, 0, "no lead, no window");
  eq((await db.getUnmatchedOutreach(env)).length, 1, "but the event is kept, not dropped");
});


console.log("\nSecurity headers");

await test("every response carries the security header set", async () => {
  const env = makeEnv();
  const { session } = await founderSession(env);
  const expected = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
  };

  const pages = [
    await worker.fetch(req("/login"), env),
    await worker.fetch(req("/dashboard", { cookies: { c7_session: session } }), env),
    await worker.fetch(req("/"), env), // a redirect
  ];
  for (const res of pages) {
    for (const [h, v] of Object.entries(expected)) eq(res.headers.get(h), v, `${h} on ${res.status}`);
    has(res.headers.get("Content-Security-Policy"), "default-src 'none'", "CSP locked down by default");
    has(res.headers.get("Strict-Transport-Security"), "max-age=31536000", "HSTS");
    has(res.headers.get("Permissions-Policy"), "geolocation=()", "Permissions-Policy");
  }
});

await test("Referrer-Policy stays permissive enough for /theme/toggle to work", async () => {
  // `no-referrer` would silently break the toggle's return-to-page behaviour,
  // which is why this is asserted rather than left to a future tidy-up.
  const env = makeEnv();
  const res = await worker.fetch(req("/login"), env);
  const policy = res.headers.get("Referrer-Policy");
  assert(policy !== "no-referrer", "must not be no-referrer");
  assert(["same-origin", "strict-origin-when-cross-origin"].includes(policy), `same-origin referrers must survive, got ${policy}`);

  const toggled = await worker.fetch(req("/theme/toggle", { headers: { Referer: `${ORIGIN}/revenue` } }), env);
  eq(toggled.headers.get("Location"), "/revenue", "still returns to the calling page");
});

await test("the CSP script hashes match the inline handlers actually emitted", async () => {
  const env = makeEnv();
  const { session, csrf } = await founderSession(env);
  await db.createLead(env, { name: "Zanele", stage: "new", contact_email: "zanele@example.com" });
  const lead = (await db.getLeads(env))[0];
  await db.flagForRetentionReview(env, "lead", lead.id, "stale");
  // A second account, so /team renders its revoke button -- that row is hidden
  // for your own user, and without it the page carries no inline handler.
  await seedFreelancer(env);

  const csp = (await worker.fetch(req("/dashboard", { cookies: { c7_session: session } }), env)).headers.get(
    "Content-Security-Policy"
  );
  const scriptSrc = csp.split(";").map((d) => d.trim()).find((d) => d.startsWith("script-src"));
  assert(scriptSrc, "CSP declares a script-src");
  has(scriptSrc, "'unsafe-hashes'", "inline handlers need unsafe-hashes alongside their digests");
  // 'unsafe-inline' is fine in style-src (see the CSP comment in index.js) but
  // must never appear in script-src -- that would defeat the whole directive.
  lacks(scriptSrc, "'unsafe-inline'", "script-src must never fall back to unsafe-inline");
  lacks(csp, "'unsafe-eval'", "no eval anywhere");

  // Must cover every page that carries an inline handler, or the
  // no-stale-digests check below fires a false positive.
  // A lead approved for outreach, with sending configured, so the lead-detail
  // page renders its confirm() handler. Without this the digest for it would
  // be missing from the CSP and nothing would notice until it broke live.
  env.MAKE_OUTREACH_URL = "https://hook.eu2.make.com/test";
  env.MAKE_WEBHOOK_SECRET = "s";
  const approved = (await db.getLeads(env))[0];
  await db.setOutreachStatus(env, approved.id, "approved", "Tester");

  const pages = await Promise.all(
    ["/leads", "/retention", "/team", `/leads/${approved.id}`].map(async (p) =>
      (await worker.fetch(req(p, { cookies: { c7_session: session } }), env)).text()
    )
  );

  // Two kinds of inline script need covering: event-handler attributes (which
  // require 'unsafe-hashes' alongside their digest) and real <script> blocks
  // (which a plain digest authorises on its own). Both must be represented.
  const handlers = new Set();
  for (const body of pages) {
    for (const m of body.matchAll(/\son(?:change|submit|click|load|error)="([^"]*)"/g)) handlers.add(m[1]);
    for (const m of body.matchAll(/<script>([\s\S]*?)<\/script>/g)) handlers.add(m[1]);
  }
  assert(handlers.size > 0, "the pages really do carry inline script to cover");

  for (const h of handlers) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(h));
    const b64 = Buffer.from(new Uint8Array(digest)).toString("base64");
    has(csp, `'sha256-${b64}'`, `CSP is missing the digest for inline handler ${JSON.stringify(h)}`);
  }

  // And nothing stale: every hash in the CSP should correspond to a real handler.
  const cspHashes = [...csp.matchAll(/'sha256-([A-Za-z0-9+/=]+)'/g)].map((m) => m[1]);
  const liveHashes = await Promise.all(
    [...handlers].map(async (h) =>
      Buffer.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(h)))).toString("base64")
    )
  );
  for (const hash of cspHashes) {
    assert(liveHashes.includes(hash), `CSP carries a digest no page emits any more: sha256-${hash}`);
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
