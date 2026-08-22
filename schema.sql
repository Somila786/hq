-- Reference copy of the schema already applied to the live D1 database
-- (catalyst7-kpi, id ba622992-c6dc-4a9b-a099-3b8a5fbe3a83).
-- Re-run this only if you ever need to rebuild the DB from scratch:
--   wrangler d1 execute catalyst7-kpi --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS freelancers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT,
  role_title TEXT,
  rate_type TEXT CHECK(rate_type IN ('hourly','project','retainer')) DEFAULT 'hourly',
  rate_amount REAL,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('founder','freelancer')),
  freelancer_id INTEGER REFERENCES freelancers(id),
  password_hash TEXT,
  password_salt TEXT,
  setup_token TEXT UNIQUE,
  created_at TEXT DEFAULT (datetime('now')),
  totp_secret TEXT,
  totp_enabled INTEGER DEFAULT 0,
  -- Google's stable subject id, bound on first Google sign-in. Email addresses
  -- can be reassigned; `sub` cannot, so this is what we pin identity to.
  google_sub TEXT,
  -- Display label only ("CEO / Co-Founder"). Access is decided by `role`.
  title TEXT
);

CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  status TEXT CHECK(status IN ('active','past')) DEFAULT 'active',
  contact_name TEXT,
  contact_email TEXT,
  source TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  company TEXT,
  contact_email TEXT,
  stage TEXT CHECK(stage IN ('new','contacted','qualified','proposal','won','lost')) DEFAULT 'new',
  value_estimate REAL,
  source TEXT,
  owner TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  -- Approval to be emailed. Deliberately separate from `stage`: stage is where
  -- the deal is, this is whether a human cleared them for outreach. Conflating
  -- them would let a pipeline move silently authorise an email.
  outreach_status TEXT DEFAULT 'pending',
  outreach_approved_by TEXT,
  outreach_approved_at TEXT,
  outreach_last_sent_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_leads_outreach ON leads (outreach_status);

CREATE TABLE IF NOT EXISTS weekly_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  week_start TEXT NOT NULL,
  freelancer_id INTEGER NOT NULL REFERENCES freelancers(id),
  hours REAL DEFAULT 0,
  deliverables TEXT,
  status TEXT CHECK(status IN ('on_track','blocked','delayed')) DEFAULT 'on_track',
  notes TEXT,
  submitted_at TEXT DEFAULT (datetime('now')),
  UNIQUE(week_start, freelancer_id)
);

CREATE TABLE IF NOT EXISTS revenue_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  week_start TEXT NOT NULL,
  client_id INTEGER REFERENCES clients(id),
  amount REAL NOT NULL,
  type TEXT CHECK(type IN ('retainer','project','platform_fee','equity','other')) DEFAULT 'project',
  invoice_status TEXT CHECK(invoice_status IN ('invoiced','paid','overdue')) DEFAULT 'invoiced',
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL,
  csrf_token TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip TEXT,
  success INTEGER NOT NULL,
  attempted_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  user_name TEXT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id INTEGER,
  detail TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  -- Who, what, when is not enough for an incident: from where, and did it
  -- work. Required by the C7 standard and useful for POPIA §17.
  ip_address TEXT,
  status TEXT DEFAULT 'success'
);

CREATE TABLE IF NOT EXISTS error_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT,
  message TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS retention_flags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  entity_id INTEGER NOT NULL,
  reason TEXT,
  flagged_at TEXT DEFAULT (datetime('now')),
  resolved INTEGER DEFAULT 0,
  resolution TEXT
);

CREATE TABLE IF NOT EXISTS pending_logins (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL
);

-- In-flight Google OAuth handshakes. Server-side and single-use: the row is
-- deleted the moment the callback consumes it, so a replayed callback fails.
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

-- Single-use 2FA recovery codes. Stored hashed; the plaintext is shown to the
-- user exactly once, at generation.
CREATE TABLE IF NOT EXISTS totp_backup_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON totp_backup_codes (user_id, used_at);

-- Self-service registration codes (see migrations/002_invite_codes.sql).
-- The role lives on the code, never on the signup form.
CREATE TABLE IF NOT EXISTS invite_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('founder','freelancer')),
  freelancer_id INTEGER REFERENCES freelancers(id),
  note TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  used_by INTEGER REFERENCES users(id),
  used_at TEXT,
  title TEXT
);

CREATE INDEX IF NOT EXISTS idx_invite_codes_open ON invite_codes (used_at, expires_at);

-- One-time nonces for form idempotency. A double-clicked create form submits
-- the same nonce twice; the second INSERT collides on the primary key and the
-- handler redirects instead of writing a duplicate record.
CREATE TABLE IF NOT EXISTS submissions (
  nonce TEXT PRIMARY KEY,
  used_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_submissions_age ON submissions (used_at);

-- ---- MCP connector / OAuth 2.1 (see migrations/005_mcp_oauth.sql) ----
-- Codes and tokens are stored as SHA-256 hashes only.

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT,
  redirect_uris TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mcp_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('access','refresh')),
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_tokens_user ON mcp_tokens (user_id, kind);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expiry ON oauth_codes (expires_at);

-- ---- Outreach ledger (see migrations/006_outreach_events.sql) ----
-- What Make actually sent, what came back, what failed. event_id is UNIQUE so
-- a webhook retry lands once.
CREATE TABLE IF NOT EXISTS outreach_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  lead_id INTEGER REFERENCES leads(id),
  lead_email TEXT,
  kind TEXT NOT NULL CHECK(kind IN ('sent','reply','bounce','failed')),
  sequence TEXT,
  step TEXT,
  subject TEXT,
  detail TEXT,
  occurred_at TEXT NOT NULL,
  received_at TEXT DEFAULT (datetime('now')),
  source TEXT
);

CREATE INDEX IF NOT EXISTS idx_outreach_lead ON outreach_events (lead_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_outreach_email ON outreach_events (lead_email);
CREATE INDEX IF NOT EXISTS idx_outreach_recent ON outreach_events (occurred_at DESC);

