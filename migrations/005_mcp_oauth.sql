-- Migration 005 — MCP connector + OAuth 2.1 authorisation server
--
-- Backs the Claude connector at POST /mcp. Claude speaks the 2025-11-25 auth
-- spec: RFC 9728 protected-resource metadata -> RFC 8414 authorization-server
-- metadata -> RFC 7591 dynamic client registration -> authorization code with
-- S256 PKCE -> bearer token.
--
-- Per-user consent is the point: a token is bound to one HQ user, so the audit
-- log keeps naming the person rather than "the connector".
--
-- Codes and tokens are credentials, so only their SHA-256 hashes are stored --
-- same reasoning as 2FA backup codes and invite codes.

-- Clients Claude registers dynamically. Public clients: no secret is issued,
-- PKCE is what binds the code to the requester.
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT,
  redirect_uris TEXT NOT NULL,       -- JSON array
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT
);

-- Authorization codes. Short-lived (60s) and single-use: redeeming deletes the
-- row, so a replayed code fails even if it hasn't expired.
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,      -- S256 only
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Access and refresh tokens. Refresh tokens rotate on use, as the spec
-- requires for public clients: the old row is deleted as the new one is
-- written, so a stolen refresh token stops working the moment the real client
-- refreshes.
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
