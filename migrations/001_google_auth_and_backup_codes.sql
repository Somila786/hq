-- Migration 001 — Google sign-in + 2FA backup codes
--
-- The live D1 database (catalyst7-kpi, ba622992-c6dc-4a9b-a099-3b8a5fbe3a83)
-- was created before these existed. schema.sql is the full picture for a
-- from-scratch rebuild; this file is what you run against the existing one.
--
--   npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/001_google_auth_and_backup_codes.sql
--
-- Safe to run more than once: the CREATEs are IF NOT EXISTS, and the ALTER is
-- the only statement that will complain on a second run ("duplicate column
-- name: google_sub"), which is harmless — everything before it has applied.

ALTER TABLE users ADD COLUMN google_sub TEXT;

CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_backup_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON totp_backup_codes (user_id, used_at);
