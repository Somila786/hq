-- Migration 002 — self-service registration via invite codes
--
--   npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/002_invite_codes.sql
--
-- Backs the "Create your account" link on the login page. A code is what
-- authorises a signup, so the role lives on the code and is never taken from
-- the registration form. Codes are stored hashed and shown to the founder
-- exactly once, same as 2FA backup codes.

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
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_invite_codes_open ON invite_codes (used_at, expires_at);
