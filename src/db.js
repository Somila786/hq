// Data access layer. Thin wrappers over D1 so index.js stays readable.

export async function getFreelancers(env, activeOnly = false) {
  const sql = activeOnly
    ? "SELECT * FROM freelancers WHERE active = 1 ORDER BY name"
    : "SELECT * FROM freelancers ORDER BY name";
  const { results } = await env.DB.prepare(sql).all();
  return results;
}

export async function getFreelancerById(env, id) {
  return env.DB.prepare("SELECT * FROM freelancers WHERE id = ?").bind(id).first();
}

export async function createFreelancer(env, f) {
  return env.DB.prepare(
    `INSERT INTO freelancers (name, email, role_title, rate_type, rate_amount) VALUES (?, ?, ?, ?, ?)`
  )
    .bind(f.name, f.email || null, f.role_title || null, f.rate_type || "hourly", f.rate_amount || null)
    .run();
}

export async function setFreelancerActive(env, id, active) {
  return env.DB.prepare("UPDATE freelancers SET active = ? WHERE id = ?").bind(active ? 1 : 0, id).run();
}

export async function getClients(env) {
  const { results } = await env.DB.prepare("SELECT * FROM clients ORDER BY status ASC, name ASC").all();
  return results;
}

export async function createClient(env, c) {
  return env.DB.prepare(
    `INSERT INTO clients (name, status, contact_name, contact_email, source, notes) VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(c.name, c.status || "active", c.contact_name || null, c.contact_email || null, c.source || null, c.notes || null)
    .run();
}

export async function setClientStatus(env, id, status) {
  return env.DB.prepare("UPDATE clients SET status = ? WHERE id = ?").bind(status, id).run();
}

export async function getLeads(env) {
  const { results } = await env.DB.prepare(
    `SELECT id, name, company, contact_email, stage, value_estimate, source, owner, notes,
            created_at, updated_at,
            COALESCE(outreach_status,'pending') AS outreach_status,
            outreach_approved_by, outreach_approved_at, outreach_last_sent_at,
            call_due_at, call_outcome, call_logged_at, call_logged_by
     FROM leads ORDER BY CASE stage WHEN 'won' THEN 1 WHEN 'lost' THEN 1 ELSE 0 END, updated_at DESC`
  ).all();
  return results;
}

export async function createLead(env, l) {
  return env.DB.prepare(
    `INSERT INTO leads (name, company, contact_email, stage, value_estimate, source, owner, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      l.name,
      l.company || null,
      l.contact_email || null,
      l.stage || "new",
      l.value_estimate || null,
      l.source || null,
      l.owner || null,
      l.notes || null
    )
    .run();
}

export async function updateLeadStage(env, id, stage) {
  return env.DB.prepare("UPDATE leads SET stage = ?, updated_at = datetime('now') WHERE id = ?").bind(stage, id).run();
}

export async function getRevenueEntries(env, limit = 50) {
  const { results } = await env.DB.prepare(
    `SELECT r.*, c.name as client_name FROM revenue_entries r
     LEFT JOIN clients c ON c.id = r.client_id
     ORDER BY r.week_start DESC, r.created_at DESC LIMIT ?`
  )
    .bind(limit)
    .all();
  return results;
}

export async function createRevenueEntry(env, r) {
  return env.DB.prepare(
    `INSERT INTO revenue_entries (week_start, client_id, amount, type, invoice_status, notes) VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(r.week_start, r.client_id || null, r.amount, r.type || "project", r.invoice_status || "invoiced", r.notes || null)
    .run();
}

export async function getWeeklyEntry(env, weekStart, freelancerId) {
  return env.DB.prepare("SELECT * FROM weekly_entries WHERE week_start = ? AND freelancer_id = ?")
    .bind(weekStart, freelancerId)
    .first();
}

export async function upsertWeeklyEntry(env, w) {
  return env.DB.prepare(
    `INSERT INTO weekly_entries (week_start, freelancer_id, hours, deliverables, status, notes)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(week_start, freelancer_id) DO UPDATE SET
       hours = excluded.hours,
       deliverables = excluded.deliverables,
       status = excluded.status,
       notes = excluded.notes,
       submitted_at = datetime('now')`
  )
    .bind(w.week_start, w.freelancer_id, w.hours || 0, w.deliverables || null, w.status || "on_track", w.notes || null)
    .run();
}

export async function getFreelancerHistory(env, freelancerId, limit = 12) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM weekly_entries WHERE freelancer_id = ? ORDER BY week_start DESC LIMIT ?"
  )
    .bind(freelancerId, limit)
    .all();
  return results;
}

// ---- Dashboard aggregates for a given week ----
export async function getDashboard(env, weekStart, prevWeekStart) {
  const db = env.DB;

  const hoursThis = await db
    .prepare("SELECT COALESCE(SUM(hours),0) as total FROM weekly_entries WHERE week_start = ?")
    .bind(weekStart)
    .first();
  const hoursPrev = await db
    .prepare("SELECT COALESCE(SUM(hours),0) as total FROM weekly_entries WHERE week_start = ?")
    .bind(prevWeekStart)
    .first();

  const revThis = await db
    .prepare("SELECT COALESCE(SUM(amount),0) as total FROM revenue_entries WHERE week_start = ?")
    .bind(weekStart)
    .first();
  const revPrev = await db
    .prepare("SELECT COALESCE(SUM(amount),0) as total FROM revenue_entries WHERE week_start = ?")
    .bind(prevWeekStart)
    .first();

  const { results: revByType } = await db
    .prepare("SELECT type, COALESCE(SUM(amount),0) as total FROM revenue_entries WHERE week_start = ? GROUP BY type")
    .bind(weekStart)
    .all();

  const { results: leadsByStage } = await db
    .prepare(
      `SELECT stage, COUNT(*) as n, COALESCE(SUM(value_estimate),0) as val
       FROM leads WHERE stage NOT IN ('won','lost') GROUP BY stage`
    )
    .all();

  const newLeads = await db
    .prepare("SELECT COUNT(*) as n FROM leads WHERE date(created_at) >= date(?)")
    .bind(weekStart)
    .first();

  const wonThis = await db
    .prepare(
      "SELECT COUNT(*) as n, COALESCE(SUM(value_estimate),0) as val FROM leads WHERE stage = 'won' AND date(updated_at) >= date(?)"
    )
    .bind(weekStart)
    .first();

  const newClients = await db
    .prepare("SELECT COUNT(*) as n FROM clients WHERE date(created_at) >= date(?)")
    .bind(weekStart)
    .first();

  const activeClients = await db.prepare("SELECT COUNT(*) as n FROM clients WHERE status = 'active'").first();

  const activeFreelancers = await getFreelancers(env, true);
  const { results: submittedIds } = await db
    .prepare("SELECT freelancer_id FROM weekly_entries WHERE week_start = ?")
    .bind(weekStart)
    .all();
  const submittedSet = new Set(submittedIds.map((r) => r.freelancer_id));
  const missing = activeFreelancers.filter((f) => !submittedSet.has(f.id));

  const pipelineValue = leadsByStage.reduce((sum, s) => sum + (s.val || 0), 0);

  return {
    weekStart,
    prevWeekStart,
    hoursThis: hoursThis.total,
    hoursPrev: hoursPrev.total,
    revThis: revThis.total,
    revPrev: revPrev.total,
    revByType,
    leadsByStage,
    pipelineValue,
    newLeads: newLeads.n,
    wonThis,
    newClients: newClients.n,
    activeClients: activeClients.n,
    activeFreelancerCount: activeFreelancers.length,
    submittedCount: submittedSet.size,
    missingFreelancers: missing,
  };
}

// ---- 2FA backup codes ----
// Codes arrive here already hashed; plaintext never reaches the database.
export async function replaceBackupCodes(env, userId, codeHashes) {
  await env.DB.prepare("DELETE FROM totp_backup_codes WHERE user_id = ?").bind(userId).run();
  for (const hash of codeHashes) {
    await env.DB.prepare("INSERT INTO totp_backup_codes (user_id, code_hash) VALUES (?, ?)").bind(userId, hash).run();
  }
}

export async function countUnusedBackupCodes(env, userId) {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) as n FROM totp_backup_codes WHERE user_id = ? AND used_at IS NULL"
  )
    .bind(userId)
    .first();
  return row.n;
}

// Redeems a backup code if it matches an unused one. Returns true exactly once
// per code -- the UPDATE's `used_at IS NULL` guard is what makes it single-use
// even if two requests race.
export async function redeemBackupCode(env, userId, codeHash) {
  const row = await env.DB.prepare(
    "SELECT id FROM totp_backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL"
  )
    .bind(userId, codeHash)
    .first();
  if (!row) return false;
  const res = await env.DB.prepare(
    "UPDATE totp_backup_codes SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL"
  )
    .bind(row.id)
    .run();
  return res.meta.changes === 1;
}

export async function clearBackupCodes(env, userId) {
  await env.DB.prepare("DELETE FROM totp_backup_codes WHERE user_id = ?").bind(userId).run();
}

// ---- Team / user accounts ----
// Never selects password_hash or password_salt -- nothing that renders a user
// list has any business holding those in memory.
export async function listUsers(env) {
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.role, u.title, u.freelancer_id, u.created_at, u.totp_enabled,
            u.setup_token IS NOT NULL AS invite_pending,
            u.password_hash IS NOT NULL AS has_password,
            u.google_sub IS NOT NULL AS google_linked,
            f.name AS freelancer_name
     FROM users u
     LEFT JOIN freelancers f ON f.id = u.freelancer_id
     ORDER BY CASE u.role WHEN 'founder' THEN 0 ELSE 1 END, u.name`
  ).all();
  return results;
}

// Credential-free. `has_password` is exposed as a flag rather than the hash
// itself, because callers only ever need to know *whether* a login works.
export async function getUserById(env, id) {
  return env.DB.prepare(
    `SELECT id, email, name, role, title, freelancer_id, totp_enabled, created_at,
            password_hash IS NOT NULL AS has_password,
            setup_token IS NOT NULL AS invite_pending,
            google_sub IS NOT NULL AS google_linked
     FROM users WHERE id = ?`
  )
    .bind(id)
    .first();
}

// Freelancer profiles that don't yet have a login attached -- the only valid
// targets when creating a freelancer account, since /log resolves a user's
// rows through freelancer_id and breaks without one.
export async function getFreelancersWithoutUser(env) {
  const { results } = await env.DB.prepare(
    `SELECT f.id, f.name FROM freelancers f
     WHERE f.active = 1
       AND NOT EXISTS (SELECT 1 FROM users u WHERE u.freelancer_id = f.id)
     ORDER BY f.name`
  ).all();
  return results;
}

export async function createUser(env, u) {
  return env.DB.prepare(
    "INSERT INTO users (email, name, role, title, freelancer_id, setup_token) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(u.email, u.name, u.role, u.title || null, u.freelancer_id || null, u.setup_token)
    .run();
}

// Display label only -- deliberately cannot touch `role`, so an edit here can
// never change what someone is allowed to see.
export async function setUserTitle(env, id, title) {
  return env.DB.prepare("UPDATE users SET title = ? WHERE id = ?")
    .bind(title || null, id)
    .run();
}

// Issuing a fresh invite clears any existing password: the link is a way back
// in for someone locked out, so the old credential must stop working.
export async function reissueSetupToken(env, id, token) {
  return env.DB.prepare(
    "UPDATE users SET setup_token = ?, password_hash = NULL, password_salt = NULL WHERE id = ?"
  )
    .bind(token, id)
    .run();
}

// Locks an account without deleting it, so audit history and any linked
// records stay intact -- same principle as the retention flow.
export async function revokeUserAccess(env, id) {
  await env.DB.prepare(
    `UPDATE users SET password_hash = NULL, password_salt = NULL, setup_token = NULL,
                      totp_secret = NULL, totp_enabled = 0, google_sub = NULL
     WHERE id = ?`
  )
    .bind(id)
    .run();
  // Kill any live session immediately -- revoking is pointless if the person
  // stays signed in on a device they already have open. Same for MCP tokens:
  // a connector holding a valid token would otherwise keep reading.
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM mcp_tokens WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM pending_logins WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM totp_backup_codes WHERE user_id = ?").bind(id).run();
}

export async function countActiveFounders(env) {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM users WHERE role = 'founder' AND password_hash IS NOT NULL"
  ).first();
  return row.n;
}

// ---- Registration invite codes ----
export async function createInviteCode(env, c) {
  await env.DB.prepare(
    `INSERT INTO invite_codes (code_hash, role, freelancer_id, note, title, created_by, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(c.code_hash, c.role, c.freelancer_id || null, c.note || null, c.title || null, c.created_by || null, c.expires_at)
    .run();
}

// Only ever returns a code that is unused AND unexpired -- the two conditions
// live here rather than at the call site so no route can forget one.
export async function findOpenInviteCode(env, codeHash) {
  return env.DB.prepare(
    `SELECT * FROM invite_codes
     WHERE code_hash = ? AND used_at IS NULL AND expires_at > datetime('now')`
  )
    .bind(codeHash)
    .first();
}

// The `used_at IS NULL` guard makes redemption single-use even if two
// registrations race for the same code.
export async function consumeInviteCode(env, id, userId) {
  const res = await env.DB.prepare(
    "UPDATE invite_codes SET used_at = datetime('now'), used_by = ? WHERE id = ? AND used_at IS NULL"
  )
    .bind(userId, id)
    .run();
  return res.meta.changes === 1;
}

export async function listInviteCodes(env) {
  const { results } = await env.DB.prepare(
    `SELECT c.id, c.role, c.note, c.title, c.created_at, c.expires_at, c.used_at,
            c.expires_at <= datetime('now') AS expired,
            f.name AS freelancer_name,
            cu.name AS created_by_name,
            uu.name AS used_by_name
     FROM invite_codes c
     LEFT JOIN freelancers f ON f.id = c.freelancer_id
     LEFT JOIN users cu ON cu.id = c.created_by
     LEFT JOIN users uu ON uu.id = c.used_by
     ORDER BY c.used_at IS NOT NULL, c.created_at DESC
     LIMIT 50`
  ).all();
  return results;
}

export async function revokeInviteCode(env, id) {
  const res = await env.DB.prepare("DELETE FROM invite_codes WHERE id = ? AND used_at IS NULL").bind(id).run();
  return res.meta.changes === 1;
}

export async function countOpenInviteCodes(env) {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM invite_codes WHERE used_at IS NULL AND expires_at > datetime('now')"
  ).first();
  return row.n;
}

// ---- Google account binding ----
// Credential-free -- used for existence checks and the Google allowlist.
export async function getUserByEmail(env, email) {
  return env.DB.prepare(
    `SELECT id, email, name, role, title, freelancer_id, totp_enabled, google_sub,
            password_hash IS NOT NULL AS has_password
     FROM users WHERE email = ?`
  )
    .bind(email)
    .first();
}

// The ONLY query that returns password material, used by the login handler and
// nothing else. Keeping it isolated means a careless `user.password_hash`
// elsewhere reads undefined rather than a real hash.
export async function getUserCredentials(env, email) {
  return env.DB.prepare(
    `SELECT id, email, name, role, password_hash, password_salt, totp_enabled
     FROM users WHERE email = ?`
  )
    .bind(email)
    .first();
}

// ---- Form idempotency ----
// Claims a one-time submission nonce. Returns true only for the first caller:
// the PRIMARY KEY makes the second INSERT fail, which is how a double-clicked
// form is detected without any locking.
export async function claimSubmission(env, nonce) {
  if (!nonce || typeof nonce !== "string" || nonce.length < 8 || nonce.length > 64) return false;
  const res = await env.DB.prepare("INSERT OR IGNORE INTO submissions (nonce) VALUES (?)").bind(nonce).run();
  return res.meta.changes === 1;
}

// Nonces only need to outlive a user's patience with a stuck form. Purged by
// the monthly cron alongside the retention scan.
export async function purgeOldSubmissions(env) {
  await env.DB.prepare("DELETE FROM submissions WHERE used_at < datetime('now', '-7 days')").run();
}

export async function bindGoogleSub(env, userId, sub) {
  await env.DB.prepare("UPDATE users SET google_sub = ? WHERE id = ?").bind(sub, userId).run();
}

// ---- MCP connector: OAuth client registry, codes, tokens ----

export async function registerOAuthClient(env, { clientId, clientName, redirectUris }) {
  await env.DB.prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)")
    .bind(clientId, clientName || null, JSON.stringify(redirectUris))
    .run();
}

export async function getOAuthClient(env, clientId) {
  const row = await env.DB.prepare(
    "SELECT client_id, client_name, redirect_uris FROM oauth_clients WHERE client_id = ?"
  )
    .bind(clientId)
    .first();
  if (!row) return null;
  let uris = [];
  try {
    uris = JSON.parse(row.redirect_uris);
  } catch {
    uris = [];
  }
  return { ...row, redirect_uris: Array.isArray(uris) ? uris : [] };
}

export async function createAuthCode(env, c) {
  await env.DB.prepare(
    `INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(c.code_hash, c.client_id, c.user_id, c.redirect_uri, c.code_challenge, c.scope, c.expires_at)
    .run();
}

// Single-use: the row is deleted as it's read, so a replayed code fails even
// inside its 60-second window.
export async function consumeAuthCode(env, codeHash) {
  const row = await env.DB.prepare(
    "SELECT * FROM oauth_codes WHERE code_hash = ? AND expires_at > datetime('now')"
  )
    .bind(codeHash)
    .first();
  await env.DB.prepare("DELETE FROM oauth_codes WHERE code_hash = ?").bind(codeHash).run();
  return row || null;
}

export async function storeMcpToken(env, t) {
  await env.DB.prepare(
    `INSERT INTO mcp_tokens (token_hash, kind, client_id, user_id, scope, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(t.token_hash, t.kind, t.client_id, t.user_id, t.scope, t.expires_at)
    .run();
}

// Resolves a bearer token to the HQ user it was issued for. Returns the same
// shape the rest of the app expects from a session, so role checks downstream
// are identical whether a request came from a browser or from Claude.
export async function getMcpTokenUser(env, tokenHash) {
  const row = await env.DB.prepare(
    `SELECT t.token_hash, t.client_id, t.scope, t.user_id,
            u.id, u.email, u.name, u.role, u.title, u.freelancer_id
     FROM mcp_tokens t JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = ? AND t.kind = 'access' AND t.expires_at > datetime('now')
       AND u.password_hash IS NOT NULL`
  )
    .bind(tokenHash)
    .first();
  if (!row) return null;
  await env.DB.prepare("UPDATE mcp_tokens SET last_used_at = datetime('now') WHERE token_hash = ?")
    .bind(tokenHash)
    .run();
  return row;
}

// Rotation, as the spec requires for public clients: reading a refresh token
// deletes it, so a stolen copy is dead the moment the real client refreshes.
export async function consumeRefreshToken(env, tokenHash) {
  const row = await env.DB.prepare(
    "SELECT * FROM mcp_tokens WHERE token_hash = ? AND kind = 'refresh' AND expires_at > datetime('now')"
  )
    .bind(tokenHash)
    .first();
  if (row) await env.DB.prepare("DELETE FROM mcp_tokens WHERE token_hash = ?").bind(tokenHash).run();
  return row || null;
}

export async function listMcpGrants(env, userId) {
  const { results } = await env.DB.prepare(
    `SELECT c.client_name, t.client_id, MIN(t.created_at) AS granted_at,
            MAX(t.last_used_at) AS last_used_at, COUNT(*) AS tokens
     FROM mcp_tokens t LEFT JOIN oauth_clients c ON c.client_id = t.client_id
     WHERE t.user_id = ? AND t.expires_at > datetime('now')
     GROUP BY t.client_id ORDER BY granted_at DESC`
  )
    .bind(userId)
    .all();
  return results;
}

export async function revokeMcpGrant(env, userId, clientId) {
  const res = await env.DB.prepare("DELETE FROM mcp_tokens WHERE user_id = ? AND client_id = ?")
    .bind(userId, clientId)
    .run();
  return res.meta.changes;
}

// Revoking a person's HQ access must also kill any connector tokens issued to
// them, or Claude keeps reading after they've been locked out.
export async function revokeAllMcpTokensForUser(env, userId) {
  await env.DB.prepare("DELETE FROM mcp_tokens WHERE user_id = ?").bind(userId).run();
}

export async function purgeExpiredOAuth(env) {
  await env.DB.prepare("DELETE FROM oauth_codes WHERE expires_at <= datetime('now')").run();
  await env.DB.prepare("DELETE FROM mcp_tokens WHERE expires_at <= datetime('now')").run();
}

// ---- Outreach ledger (events posted in by Make) ----

// INSERT OR IGNORE on the UNIQUE event_id is the idempotency mechanism: a Make
// retry lands once. Returns false when the event was already recorded, so the
// caller can answer 200 without double-counting.
export async function recordOutreachEvent(env, e) {
  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO outreach_events
       (event_id, lead_id, lead_email, kind, sequence, step, subject, detail, occurred_at, source)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      e.event_id,
      e.lead_id || null,
      e.lead_email || null,
      e.kind,
      e.sequence || null,
      e.step || null,
      e.subject || null,
      e.detail || null,
      e.occurred_at,
      e.source || null
    )
    .run();
  return res.meta.changes === 1;
}

// Matching is by email, lowercased. A send to an address that isn't in the
// pipeline still gets recorded with lead_id NULL rather than dropped.
export async function findLeadByEmail(env, email) {
  if (!email) return null;
  return env.DB.prepare(
    "SELECT id, name, company, stage FROM leads WHERE lower(contact_email) = lower(?) LIMIT 1"
  )
    .bind(email)
    .first();
}

export async function getLeadById(env, id) {
  return env.DB.prepare(
    `SELECT id, name, company, contact_email, stage, value_estimate, source, owner, notes,
            created_at, updated_at,
            COALESCE(outreach_status,'pending') AS outreach_status,
            outreach_approved_by, outreach_approved_at, outreach_last_sent_at,
            call_due_at, call_outcome, call_logged_at, call_logged_by
     FROM leads WHERE id = ?`
  )
    .bind(id)
    .first();
}

export async function getOutreachForLead(env, leadId, limit = 50) {
  const { results } = await env.DB.prepare(
    `SELECT kind, sequence, step, subject, detail, occurred_at, source
     FROM outreach_events WHERE lead_id = ? ORDER BY occurred_at DESC LIMIT ?`
  )
    .bind(leadId, limit)
    .all();
  return results;
}

// Recent activity across every lead, for the CRM overview.
export async function getRecentOutreach(env, limit = 50) {
  const { results } = await env.DB.prepare(
    `SELECT o.kind, o.sequence, o.step, o.subject, o.detail, o.occurred_at, o.lead_email,
            o.lead_id, l.name AS lead_name, l.company AS lead_company
     FROM outreach_events o LEFT JOIN leads l ON l.id = o.lead_id
     ORDER BY o.occurred_at DESC LIMIT ?`
  )
    .bind(limit)
    .all();
  return results;
}

// Per-lead counts, so the leads table can show outreach at a glance without
// N queries.
export async function getOutreachSummary(env) {
  const { results } = await env.DB.prepare(
    `SELECT lead_id,
            SUM(kind = 'sent') AS sent,
            SUM(kind = 'reply') AS replies,
            SUM(kind IN ('bounce','failed')) AS problems,
            MAX(occurred_at) AS last_at
     FROM outreach_events WHERE lead_id IS NOT NULL GROUP BY lead_id`
  ).all();
  return Object.fromEntries(results.map((r) => [r.lead_id, r]));
}

// Events whose address matched no lead -- worth surfacing rather than hiding,
// since it usually means a typo or a lead deleted mid-sequence.
export async function getUnmatchedOutreach(env, limit = 20) {
  const { results } = await env.DB.prepare(
    `SELECT kind, lead_email, subject, occurred_at FROM outreach_events
     WHERE lead_id IS NULL ORDER BY occurred_at DESC LIMIT ?`
  )
    .bind(limit)
    .all();
  return results;
}

// ---- Outreach approval gate ----
// Approval is a separate axis from `stage`; only an explicitly approved lead
// with an email address can be sent to.
export async function setOutreachStatus(env, id, status, actor) {
  return env.DB.prepare(
    `UPDATE leads SET outreach_status = ?,
            outreach_approved_by = CASE WHEN ? = 'approved' THEN ? ELSE NULL END,
            outreach_approved_at = CASE WHEN ? = 'approved' THEN datetime('now') ELSE NULL END
     WHERE id = ?`
  )
    .bind(status, status, actor || null, status, id)
    .run();
}

// A successful send is what opens the Sequence B call window, so the two are
// stamped together. Doing it here rather than in the route means there is no
// path that records a send without also putting the call on the tracker --
// which was the exact failure the decision log describes as "off the tracker".
//
// Any prior outcome is cleared: a re-send starts a fresh window, and leaving the
// old outcome would attribute a previous call to the new one.
export async function markOutreachSent(env, id, windowHours = 18) {
  const hours = Math.min(168, Math.max(1, Math.round(Number(windowHours) || 18)));
  return env.DB.prepare(
    `UPDATE leads
        SET outreach_last_sent_at = datetime('now'),
            call_due_at = datetime('now', ?),
            call_outcome = NULL,
            call_logged_at = NULL,
            call_logged_by = NULL
      WHERE id = ?`
  )
    .bind(`+${hours} hours`, id)
    .run();
}

// ---- The call window (CRM step 3) ----
//
// Sequence B calls REGARDLESS of whether the lead replied, so this queue is
// deliberately not filtered by reply state. `replied_since_send` is carried
// along as context for the person making the call, not as a reason to skip it.
export const CALL_OUTCOMES = ["picked_up_cold", "replied_first", "no_response", "skipped"];

export const CALL_OUTCOME_LABELS = {
  picked_up_cold: "Picked up cold",
  replied_first: "Replied first",
  no_response: "No response",
  skipped: "Skipped",
};

export async function getCallQueue(env, limit = 200) {
  const { results } = await env.DB.prepare(
    `SELECT l.id, l.name, l.company, l.contact_email, l.stage, l.owner, l.source,
            l.value_estimate, l.outreach_last_sent_at, l.call_due_at,
            l.call_due_at <= datetime('now') AS due_now,
            EXISTS (
              SELECT 1 FROM outreach_events o
               WHERE o.lead_id = l.id AND o.kind = 'reply'
                 AND o.occurred_at >= COALESCE(l.outreach_last_sent_at, '0000')
            ) AS replied_since_send
       FROM leads l
      WHERE l.call_due_at IS NOT NULL AND l.call_outcome IS NULL
      ORDER BY l.call_due_at ASC
      LIMIT ?`
  )
    .bind(limit)
    .all();
  return results;
}

export async function countCallQueue(env) {
  const row = await env.DB.prepare(
    `SELECT
       SUM(call_due_at <= datetime('now')) AS due,
       SUM(call_due_at >  datetime('now')) AS waiting
     FROM leads WHERE call_due_at IS NOT NULL AND call_outcome IS NULL`
  ).first();
  return { due: row?.due || 0, waiting: row?.waiting || 0 };
}

// The comparable data the sequence exists to produce. `skipped` is counted but
// kept out of `comparable`, because a call that never happened says nothing
// about whether calling works.
export async function getCallOutcomeStats(env) {
  const { results } = await env.DB.prepare(
    `SELECT call_outcome AS outcome, COUNT(*) AS n
       FROM leads WHERE call_outcome IS NOT NULL GROUP BY call_outcome`
  ).all();
  const by = Object.fromEntries(results.map((r) => [r.outcome, r.n]));
  const counts = Object.fromEntries(CALL_OUTCOMES.map((o) => [o, by[o] || 0]));
  counts.comparable = counts.picked_up_cold + counts.replied_first + counts.no_response;
  return counts;
}

// Closes the window and writes the call into the ledger in one go. The event
// carries the same wording the queue showed, so the timeline and the queue can
// never disagree about what was recorded.
export async function logCallOutcome(env, { leadId, leadEmail, outcome, notes, actor }) {
  if (!CALL_OUTCOMES.includes(outcome)) throw new Error(`unknown call outcome: ${outcome}`);
  const occurredAt = new Date().toISOString();
  await recordOutreachEvent(env, {
    event_id: `evt_call_${crypto.randomUUID()}`,
    lead_id: leadId,
    lead_email: leadEmail || null,
    kind: "call",
    sequence: "sequence_b",
    step: "call",
    subject: CALL_OUTCOME_LABELS[outcome],
    detail: notes ? String(notes).slice(0, 1000) : null,
    occurred_at: occurredAt,
    source: "catalyst7_hq",
  });
  await env.DB.prepare(
    `UPDATE leads SET call_outcome = ?, call_logged_at = datetime('now'), call_logged_by = ?
      WHERE id = ?`
  )
    .bind(outcome, actor || null, leadId)
    .run();
  return occurredAt;
}

// Reopening is a correction, not a new window: it clears the outcome and puts
// the lead back where it was, rather than pretending a fresh send happened.
// The logged call stays in the ledger -- the record of what was done is not
// something a correction gets to erase.
export async function reopenCallWindow(env, id) {
  return env.DB.prepare(
    `UPDATE leads SET call_outcome = NULL, call_logged_at = NULL, call_logged_by = NULL
      WHERE id = ?`
  )
    .bind(id)
    .run();
}

// The review queue: everything still awaiting a decision, newest first.
export async function getLeadsAwaitingApproval(env, limit = 100) {
  const { results } = await env.DB.prepare(
    `SELECT id, name, company, contact_email, stage, source, value_estimate, created_at
     FROM leads
     WHERE COALESCE(outreach_status,'pending') = 'pending'
     ORDER BY created_at DESC LIMIT ?`
  )
    .bind(limit)
    .all();
  return results;
}

export async function countOutreachQueue(env) {
  const row = await env.DB.prepare(
    `SELECT
       SUM(COALESCE(outreach_status,'pending') = 'pending') AS pending,
       SUM(outreach_status = 'approved') AS approved,
       SUM(outreach_status = 'rejected') AS rejected
     FROM leads`
  ).first();
  return { pending: row.pending || 0, approved: row.approved || 0, rejected: row.rejected || 0 };
}

// ---- Audit log ----
// `ip` and `status` are required by the C7 standard: who/what/when alone
// doesn't support an incident investigation without where and whether-it-worked.
export async function logAudit(env, user, action, entityType, entityId, detail, ip = null, status = "success") {
  await env.DB.prepare(
    `INSERT INTO audit_log (user_id, user_name, action, entity_type, entity_id, detail, ip_address, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      user ? user.id : null,
      user ? user.name : "system",
      action,
      entityType || null,
      entityId || null,
      detail || null,
      ip || null,
      status || "success"
    )
    .run();
}

export async function getAuditLog(env, limit = 100) {
  const { results } = await env.DB.prepare(
    `SELECT created_at, user_name, action, entity_type, entity_id, detail, ip_address, status
     FROM audit_log ORDER BY created_at DESC LIMIT ?`
  )
    .bind(limit)
    .all();
  return results;
}

// ---- Error log ----
export async function logError(env, path, message) {
  try {
    await env.DB.prepare("INSERT INTO error_log (path, message) VALUES (?, ?)").bind(path, String(message).slice(0, 2000)).run();
  } catch (_) {
    // If logging itself fails, don't let that mask the original error.
  }
}

export async function getErrorLog(env, limit = 100) {
  const { results } = await env.DB.prepare("SELECT * FROM error_log ORDER BY created_at DESC LIMIT ?").bind(limit).all();
  return results;
}

// ---- Retention review ----
export async function flagForRetentionReview(env, entityType, entityId, reason) {
  const existing = await env.DB.prepare(
    "SELECT id FROM retention_flags WHERE entity_type = ? AND entity_id = ? AND resolved = 0"
  )
    .bind(entityType, entityId)
    .first();
  if (existing) return; // already flagged and awaiting review
  await env.DB.prepare("INSERT INTO retention_flags (entity_type, entity_id, reason) VALUES (?, ?, ?)")
    .bind(entityType, entityId, reason)
    .run();
}

export async function getOpenRetentionFlags(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM retention_flags WHERE resolved = 0 ORDER BY flagged_at ASC"
  ).all();
  // Attach a human label for each flagged entity
  for (const f of results) {
    if (f.entity_type === "lead") {
      const row = await env.DB.prepare("SELECT name, company FROM leads WHERE id = ?").bind(f.entity_id).first();
      f.label = row ? `${row.name}${row.company ? " (" + row.company + ")" : ""}` : "(deleted)";
    } else if (f.entity_type === "freelancer") {
      const row = await env.DB.prepare("SELECT name FROM freelancers WHERE id = ?").bind(f.entity_id).first();
      f.label = row ? row.name : "(deleted)";
    }
  }
  return results;
}

export async function resolveRetentionFlag(env, id, resolution) {
  await env.DB.prepare("UPDATE retention_flags SET resolved = 1, resolution = ? WHERE id = ?").bind(resolution, id).run();
}

export async function eraseLeadPII(env, id) {
  await env.DB.prepare(
    "UPDATE leads SET name = '[erased]', company = NULL, contact_email = NULL, notes = NULL WHERE id = ?"
  )
    .bind(id)
    .run();
}

export async function eraseFreelancerPII(env, id) {
  await env.DB.prepare("UPDATE freelancers SET name = '[erased]', email = NULL WHERE id = ?").bind(id).run();
  await env.DB.prepare("UPDATE users SET name = '[erased]', email = 'erased-' || id || '@placeholder.local' WHERE freelancer_id = ?")
    .bind(id)
    .run();
}

// Scans for stale records worth a human retention decision. Called from the
// monthly Cron Trigger -- never deletes anything itself, only flags.
export async function runRetentionScan(env) {
  const { results: staleLeads } = await env.DB.prepare(
    "SELECT id FROM leads WHERE stage = 'lost' AND date(updated_at) < date('now', '-365 days')"
  ).all();
  for (const l of staleLeads) {
    await flagForRetentionReview(env, "lead", l.id, "Lost lead, no activity in 365+ days");
  }

  const { results: staleFreelancers } = await env.DB.prepare(
    `SELECT f.id FROM freelancers f
     WHERE f.active = 0
       AND NOT EXISTS (
         SELECT 1 FROM weekly_entries w WHERE w.freelancer_id = f.id AND date(w.submitted_at) > date('now', '-365 days')
       )`
  ).all();
  for (const f of staleFreelancers) {
    await flagForRetentionReview(env, "freelancer", f.id, "Inactive freelancer, no logged activity in 365+ days");
  }

  return { leadsFlagged: staleLeads.length, freelancersFlagged: staleFreelancers.length };
}
