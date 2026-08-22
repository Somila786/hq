-- Migration 008 — the call window and outcome log (CRM step 3)
--
--   Run in the D1 console, or:
--   npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/008_call_window.sql
--
-- Sequence B (adopted 16 Aug 2026) is: send, wait a short defined window, then
-- call REGARDLESS of whether they replied, then log the outcome.
--
-- The Call-Timing Decision Log names this as the sequence's one unbuilt
-- dependency -- "needs a tracked window per lead, a scheduling/reminder
-- mechanism not yet built" -- and lists step 9 (Wait / Call) as the only step
-- with "no tool, human, off the tracker". This migration puts it on the
-- tracker.
--
-- Two pieces:
--   1. The window state lives on the lead. It is a projection of "what is due
--      now", not history.
--   2. The outcome is written into outreach_events, because that table is
--      already the record of what happened to a lead and a call is the most
--      consequential thing in the sequence. Keeping calls out of it would mean
--      the timeline lied by omission.

-- ---- 1. Widen the ledger to admit calls ----
--
-- SQLite cannot ALTER a CHECK constraint, so the table is rebuilt. This is the
-- standard rebuild pattern and it preserves every existing row.
--
-- Note the webhook does NOT accept kind='call'. Calls are logged by a founder
-- inside HQ; Make has no way to know a call happened. The constraint is widened
-- here, and src/index.js keeps the inbound allowlist at the original four.

CREATE TABLE IF NOT EXISTS outreach_events_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  lead_id INTEGER REFERENCES leads(id),
  lead_email TEXT,
  kind TEXT NOT NULL CHECK(kind IN ('sent','reply','bounce','failed','call')),
  sequence TEXT,
  step TEXT,
  subject TEXT,
  detail TEXT,
  occurred_at TEXT NOT NULL,
  received_at TEXT DEFAULT (datetime('now')),
  source TEXT
);

INSERT INTO outreach_events_new
  (id, event_id, lead_id, lead_email, kind, sequence, step, subject, detail, occurred_at, received_at, source)
SELECT
   id, event_id, lead_id, lead_email, kind, sequence, step, subject, detail, occurred_at, received_at, source
FROM outreach_events;

DROP TABLE outreach_events;
ALTER TABLE outreach_events_new RENAME TO outreach_events;

CREATE INDEX IF NOT EXISTS idx_outreach_lead ON outreach_events (lead_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_outreach_email ON outreach_events (lead_email);
CREATE INDEX IF NOT EXISTS idx_outreach_recent ON outreach_events (occurred_at DESC);

-- ---- 2. The window, on the lead ----
--
-- call_due_at is stamped when a send succeeds. It is when the window CLOSES,
-- i.e. the earliest the call should be made. It never blocks a call: a founder
-- who wants to call the same day just calls and logs it. The due time decides
-- ordering and prominence in the queue, nothing more. That matters -- a tool
-- that refused an early call would be fighting the operator.
--
-- call_outcome uses the decision log's own three buckets, plus one:
--   picked_up_cold -- answered the call, had not replied to the email first
--   replied_first  -- had already replied to the email before the call landed
--   no_response    -- no email reply and the call went unanswered
--   skipped        -- deliberately not called, so the queue can be cleared
--                     honestly rather than by leaving rows to rot
--
-- The first three are the comparable data the sequence exists to produce.
-- `skipped` is excluded from that comparison on purpose.

ALTER TABLE leads ADD COLUMN call_due_at TEXT;
ALTER TABLE leads ADD COLUMN call_outcome TEXT;
ALTER TABLE leads ADD COLUMN call_logged_at TEXT;
ALTER TABLE leads ADD COLUMN call_logged_by TEXT;

-- Partial index: the queue only ever asks for windows still open.
CREATE INDEX IF NOT EXISTS idx_leads_call_due ON leads (call_due_at) WHERE call_outcome IS NULL;
