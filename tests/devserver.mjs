// Local preview server -- `npm run preview`, then open http://localhost:8788.
//
// Runs the real Worker (`src/index.js`) against an in-memory SQLite database
// seeded with throwaway demo data, so the UI can be eyeballed at any viewport
// without Cloudflare credentials, a live D1, or a deploy. `wrangler dev` is
// still the higher-fidelity option; this exists so a design change can be
// checked in seconds and offline.
//
// Dev convenience: requests arrive pre-authenticated as the demo founder, so
// there is no login step. Never used in production -- nothing imports this.

import { createServer } from "node:http";
import worker from "../src/index.js";
import { setPassword, createSession, generateTotpSecret, generateBackupCodes, hashBackupCode } from "../src/auth.js";
import * as db from "../src/db.js";
import { makeEnv } from "./d1.mjs";

const PORT = Number(process.env.PORT || 8788);

const env = makeEnv();

// Google sign-in renders whenever a client id is present. Real credentials are
// picked up from the shell if you export them; otherwise a placeholder makes
// the button visible for layout checks (clicking it will not complete a real
// sign-in, which is fine -- the flow itself is covered by tests/run.mjs).
env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "preview-placeholder.apps.googleusercontent.com";
env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "preview-placeholder-secret";

// ------------------------------------------------------------------- seed --

await env.DB.prepare("INSERT INTO users (email, name, role) VALUES ('founder@catalyst7.test', 'Thembalethu', 'founder')").run();
const founder = await env.DB.prepare("SELECT * FROM users WHERE email = 'founder@catalyst7.test'").first();
await setPassword(env, founder.id, "preview-only-password");
let SESSION = await createSession(env, founder.id);

// /logout deletes the session row, which would otherwise brick the preview
// for every later request. Re-mint on demand so the nav's "Log out" link is
// harmless here.
async function liveSession() {
  const row = await env.DB.prepare("SELECT token FROM sessions WHERE token = ?").bind(SESSION).first();
  if (!row) SESSION = await createSession(env, founder.id);
  return SESSION;
}

for (const f of [
  { name: "Naledi Khumalo", email: "naledi@example.com", role_title: "Designer", rate_type: "hourly", rate_amount: 650 },
  { name: "Sipho Dlamini", email: "sipho@example.com", role_title: "Developer", rate_type: "project", rate_amount: 18000 },
  { name: "Lerato Mokoena", email: "lerato@example.com", role_title: "Copywriter", rate_type: "hourly", rate_amount: 480 },
]) {
  await db.createFreelancer(env, f);
}

for (const c of [
  { name: "Umlazi Foods", contact_name: "Zanele Buthelezi", source: "referral" },
  { name: "Rivonia Retail Group", contact_name: "Ayanda Nkosi", source: "outbound" },
  { name: "Kaya Logistics", status: "past", contact_name: "Peter Mahlangu", source: "referral" },
]) {
  await db.createClient(env, c);
}

for (const l of [
  { name: "Thandi Mokoena", company: "Braamfontein Bakery", stage: "qualified", value_estimate: 25000, owner: "Somila", contact_email: "thandi@bakery.test" },
  { name: "Johan Pretorius", company: "Centurion Motors", stage: "proposal", value_estimate: 84000, owner: "Lethu", contact_email: "johan@motors.test" },
  { name: "Fatima Patel", company: "Laudium Textiles", stage: "new", value_estimate: 12000, owner: "Thembalethu", contact_email: "fatima@textiles.test" },
  { name: "Bongani Zulu", company: "Soweto Sound", stage: "won", value_estimate: 46000, owner: "Somila" },
  { name: "Old Prospect", company: "Dormant Co", stage: "lost", value_estimate: 9000, owner: "Lethu" },
]) {
  await db.createLead(env, l);
}

// Sequence B call windows, so /calls has all three of its states to look at:
// one overdue, one still open, and one where the lead replied but is called
// anyway. Timestamps are written directly because the real path (a successful
// send) would need a live Make endpoint.
const previewLeads = await db.getLeads(env);
const byName = (n) => previewLeads.find((l) => l.name === n);

await env.DB.prepare(
  "UPDATE leads SET outreach_status='approved', outreach_last_sent_at=datetime('now','-2 days'), call_due_at=datetime('now','-30 hours') WHERE id = ?"
)
  .bind(byName("Thandi Mokoena").id)
  .run();

await env.DB.prepare(
  "UPDATE leads SET outreach_status='approved', outreach_last_sent_at=datetime('now','-2 hours'), call_due_at=datetime('now','+16 hours') WHERE id = ?"
)
  .bind(byName("Johan Pretorius").id)
  .run();

await env.DB.prepare(
  "UPDATE leads SET outreach_status='approved', outreach_last_sent_at=datetime('now','-20 hours'), call_due_at=datetime('now','-2 hours') WHERE id = ?"
)
  .bind(byName("Fatima Patel").id)
  .run();

await db.recordOutreachEvent(env, {
  event_id: "evt_preview_sent",
  lead_id: byName("Fatima Patel").id,
  lead_email: "fatima@textiles.test",
  kind: "sent",
  sequence: "cold_outreach_v2",
  subject: "Quick question about Laudium Textiles",
  occurred_at: new Date(Date.now() - 20 * 3600_000).toISOString(),
  source: "make_outreach",
});
await db.recordOutreachEvent(env, {
  event_id: "evt_preview_reply",
  lead_id: byName("Fatima Patel").id,
  lead_email: "fatima@textiles.test",
  kind: "reply",
  subject: "Re: Quick question about Laudium Textiles",
  detail: "Interested, send more detail.",
  occurred_at: new Date(Date.now() - 3 * 3600_000).toISOString(),
  source: "make_outreach",
});

// One already-logged call, so the outcome stats aren't all zero.
await env.DB.prepare(
  "UPDATE leads SET outreach_status='approved', outreach_last_sent_at=datetime('now','-3 days'), call_due_at=datetime('now','-2 days') WHERE id = ?"
)
  .bind(byName("Bongani Zulu").id)
  .run();
await db.logCallOutcome(env, {
  leadId: byName("Bongani Zulu").id,
  leadEmail: null,
  outcome: "picked_up_cold",
  notes: "Answered, booked a follow-up for Thursday.",
  actor: "Thembalethu",
});

const monday = new Date();
monday.setUTCDate(monday.getUTCDate() - ((monday.getUTCDay() || 7) - 1));
const weekStart = monday.toISOString().slice(0, 10);
const prevWeek = new Date(monday);
prevWeek.setUTCDate(prevWeek.getUTCDate() - 7);
const prevWeekStart = prevWeek.toISOString().slice(0, 10);

const clients = await db.getClients(env);
await db.createRevenueEntry(env, { week_start: weekStart, client_id: clients[0].id, amount: 12400, type: "project", invoice_status: "paid" });
await db.createRevenueEntry(env, { week_start: weekStart, client_id: clients[1].id, amount: 22000, type: "retainer", invoice_status: "invoiced" });
await db.createRevenueEntry(env, { week_start: prevWeekStart, client_id: clients[0].id, amount: 18000, type: "project", invoice_status: "overdue" });

const freelancers = await db.getFreelancers(env);
await db.upsertWeeklyEntry(env, {
  week_start: weekStart,
  freelancer_id: freelancers[0].id,
  hours: 22.5,
  deliverables: "Brand board v2, three social templates",
  status: "on_track",
});
await db.upsertWeeklyEntry(env, {
  week_start: prevWeekStart,
  freelancer_id: freelancers[0].id,
  hours: 18,
  deliverables: "Discovery workshop",
  status: "on_track",
});

// 2FA on with a full set of backup codes, so /security shows its populated
// state rather than the empty one.
await env.DB.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?")
  .bind(generateTotpSecret(), founder.id)
  .run();
await db.replaceBackupCodes(env, founder.id, await Promise.all(generateBackupCodes().map(hashBackupCode)));

await db.logAudit(env, founder, "client_created", "client", clients[0].id, "Umlazi Foods");
await db.logAudit(env, founder, "lead_stage_changed", "lead", 4, "won");
await db.logAudit(env, founder, "revenue_logged", "revenue", null, "12400 (project)");
await db.flagForRetentionReview(env, "lead", 5, "Lost lead, no activity in 365+ days");
await db.logError(env, "/leads", "TypeError: example error row for the /errors page");

// ----------------------------------------------------------------- server --

function toRequest(req, session) {
  const url = `http://localhost:${PORT}${req.url}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) v.forEach((x) => headers.append(k, x));
    else if (v !== undefined) headers.set(k, v);
  }
  // Pre-authenticate as the demo founder, but leave any theme cookie the
  // browser is holding untouched so /theme/toggle behaves exactly as it does
  // in production.
  const cookie = headers.get("Cookie") || "";
  // Leave the auth pages genuinely signed out so they can be previewed;
  // everything else arrives pre-authenticated.
  const isAuthPage = /^\/(login|auth|setup)(\/|$)/.test(new URL(url).pathname);
  if (!isAuthPage && !cookie.includes("c7_session=")) {
    headers.set("Cookie", (cookie ? cookie + "; " : "") + `c7_session=${session}`);
  }

  const init = { method: req.method, headers };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = req;
    init.duplex = "half";
  }
  return new Request(url, init);
}

createServer(async (req, res) => {
  try {
    const wreq = toRequest(req, await liveSession());
    if (process.env.DEBUG_PREVIEW) {
      console.log(`[dbg] ${req.method} ${req.url} cookie=${JSON.stringify(wreq.headers.get("Cookie"))}`);
    }
    const workerRes = await worker.fetch(wreq, env);
    const headers = {};
    for (const [k, v] of workerRes.headers.entries()) {
      if (k.toLowerCase() !== "set-cookie") headers[k] = v;
    }
    const cookies = workerRes.headers.getSetCookie();
    if (cookies.length) {
      // `Secure` would be dropped over plain http on a non-localhost host;
      // strip it here so the preview works from any address.
      headers["set-cookie"] = cookies.map((c) => c.replace(/;\s*Secure/i, ""));
    }
    res.writeHead(workerRes.status, headers);
    res.end(Buffer.from(await workerRes.arrayBuffer()));
  } catch (err) {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end(String(err.stack || err));
  }
}).listen(PORT, () => {
  console.log(`Catalyst 7 KPI preview on http://localhost:${PORT} (signed in as Thembalethu, founder)`);
});
