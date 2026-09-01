-- Migration 010 — the coordinator role
--
-- Adds a third role, 'coordinator', between founder and freelancer, and the
-- assignment columns that scope what a coordinator sees.
--
-- SQLite cannot ALTER a CHECK constraint in place, so `users` and
-- `invite_codes` are rebuilt. `owner_user_id` on `leads`/`clients` are plain
-- ALTER ADDs.
--
-- ============================================================================
-- D1-SPECIFIC, LEARNED THE HARD WAY (31 Aug 2026):
--   * The Cloudflare D1 query path runs with FOREIGN KEYS ENFORCED and wraps
--     each call in a transaction, so `PRAGMA foreign_keys=OFF` is a no-op here
--     (it cannot be changed inside a transaction). The classic
--     off -> rebuild -> on recipe does NOT work on D1.
--   * `PRAGMA defer_foreign_keys=ON` lets the DROP happen mid-transaction, but
--     dropping a table that other tables reference trips SQLite's deferred-FK
--     *counter*, which fails the COMMIT even when `foreign_key_check` is clean
--     and no row is actually orphaned.
--   * The working recipe: within ONE atomic call, back up + empty every child
--     table that has rows referencing users, rebuild users, then restore the
--     rows. Children are empty at DROP time, so the counter stays 0. Fully
--     non-destructive: same ids in, same rows back.
--
-- HOW TO RUN via the Cloudflare D1 MCP `d1_database_query`: run each of the
-- FOUR blocks below as its own call, in order. Blocks 1-2 are single ALTERs.
-- Block 3 (users) and Block 4 (invite_codes) are each one multi-statement
-- call that D1 runs atomically. Verify with PRAGMA table_info(users) and a
-- test insert of role='coordinator'.
-- ============================================================================

-- ---- Block 1: leads.owner_user_id ----
ALTER TABLE leads ADD COLUMN owner_user_id INTEGER REFERENCES users(id);

-- ---- Block 2: clients.owner_user_id ----
ALTER TABLE clients ADD COLUMN owner_user_id INTEGER REFERENCES users(id);

-- ---- Block 3: rebuild users (widen role CHECK to include 'coordinator') ----
-- Back up/empty/restore the child tables that hold rows referencing users
-- (sessions, mcp_tokens, totp_backup_codes; add any other non-empty child that
-- references users(id) at run time). oauth_codes / invite_codes / leads /
-- clients had no referencing rows, so they need no backup.
PRAGMA defer_foreign_keys=ON;
CREATE TABLE _bak_sessions AS SELECT * FROM sessions;
DELETE FROM sessions;
CREATE TABLE _bak_mcp_tokens AS SELECT * FROM mcp_tokens;
DELETE FROM mcp_tokens;
CREATE TABLE _bak_backup_codes AS SELECT * FROM totp_backup_codes;
DELETE FROM totp_backup_codes;
CREATE TABLE users_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('founder','coordinator','freelancer')),
  freelancer_id INTEGER REFERENCES freelancers(id),
  password_hash TEXT,
  password_salt TEXT,
  setup_token TEXT UNIQUE,
  created_at TEXT DEFAULT (datetime('now')),
  totp_secret TEXT,
  totp_enabled INTEGER DEFAULT 0,
  google_sub TEXT,
  title TEXT
);
INSERT INTO users_new (id, email, name, role, freelancer_id, password_hash, password_salt, setup_token, created_at, totp_secret, totp_enabled, google_sub, title)
  SELECT id, email, name, role, freelancer_id, password_hash, password_salt, setup_token, created_at, totp_secret, totp_enabled, google_sub, title FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
INSERT INTO sessions SELECT * FROM _bak_sessions;
DROP TABLE _bak_sessions;
INSERT INTO mcp_tokens SELECT * FROM _bak_mcp_tokens;
DROP TABLE _bak_mcp_tokens;
INSERT INTO totp_backup_codes SELECT * FROM _bak_backup_codes;
DROP TABLE _bak_backup_codes;

-- ---- Block 4: rebuild invite_codes (same CHECK widening) ----
-- Nothing references invite_codes, so a plain drop+recreate is safe (no counter
-- issue). It also carries FKs TO users/freelancers, so defer while it swaps.
PRAGMA defer_foreign_keys=ON;
CREATE TABLE invite_codes_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('founder','coordinator','freelancer')),
  freelancer_id INTEGER REFERENCES freelancers(id),
  note TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  used_by INTEGER REFERENCES users(id),
  used_at TEXT,
  title TEXT
);
INSERT INTO invite_codes_new (id, code_hash, role, freelancer_id, note, created_by, created_at, expires_at, used_by, used_at, title)
  SELECT id, code_hash, role, freelancer_id, note, created_by, created_at, expires_at, used_by, used_at, title FROM invite_codes;
DROP TABLE invite_codes;
ALTER TABLE invite_codes_new RENAME TO invite_codes;
CREATE INDEX IF NOT EXISTS idx_invite_codes_open ON invite_codes (used_at, expires_at);
