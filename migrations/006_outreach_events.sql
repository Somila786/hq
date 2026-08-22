-- Migration 006 — outreach event ingestion (CRM step 1)
--
--   Run in the D1 console, or:
--   npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/006_outreach_events.sql
--
-- HQ records what Make does. Make still owns sending and the email copy; this
-- table is the ledger of what actually went out, what came back, and what
-- failed, hung off the lead it relates to.
--
-- `event_id` is UNIQUE on purpose: it carries the id from the C7 webhook
-- envelope, so a Make retry (or a double-fire) lands once instead of
-- duplicating the timeline. That is the whole idempotency mechanism.

CREATE TABLE IF NOT EXISTS outreach_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  lead_id INTEGER REFERENCES leads(id),
  -- Kept even when no lead matches, so a send to an address that isn't in the
  -- pipeline is still visible rather than silently dropped.
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
