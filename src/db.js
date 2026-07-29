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
    "SELECT * FROM leads ORDER BY CASE stage WHEN 'won' THEN 1 WHEN 'lost' THEN 1 ELSE 0 END, updated_at DESC"
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

export async function getUserById(env, id) {
  return env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
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
  // stays signed in on a device they already have open.
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
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
export async function getUserByEmail(env, email) {
  return env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
}

export async function bindGoogleSub(env, userId, sub) {
  await env.DB.prepare("UPDATE users SET google_sub = ? WHERE id = ?").bind(sub, userId).run();
}

// ---- Audit log ----
export async function logAudit(env, user, action, entityType, entityId, detail) {
  await env.DB.prepare(
    `INSERT INTO audit_log (user_id, user_name, action, entity_type, entity_id, detail) VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(user ? user.id : null, user ? user.name : "system", action, entityType || null, entityId || null, detail || null)
    .run();
}

export async function getAuditLog(env, limit = 100) {
  const { results } = await env.DB.prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?")
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
