-- Migration 007 — outreach approval gate (CRM step 2)
--
-- The pipeline is: Apify scrapes -> a founder qualifies in HQ -> a founder
-- approves -> HQ triggers Make to send. This migration adds the approval gate.
--
-- `outreach_status` is deliberately SEPARATE from `stage`. Stage says where a
-- deal is (new/contacted/qualified/proposal/won/lost); approval says whether a
-- human has cleared this person to be emailed. Conflating them would mean
-- moving a deal along the pipeline could silently authorise an email.
--
-- Nothing is emailed without an explicit approval, and every approval records
-- who made it.

ALTER TABLE leads ADD COLUMN outreach_status TEXT DEFAULT 'pending';
ALTER TABLE leads ADD COLUMN outreach_approved_by TEXT;
ALTER TABLE leads ADD COLUMN outreach_approved_at TEXT;
ALTER TABLE leads ADD COLUMN outreach_last_sent_at TEXT;

CREATE INDEX IF NOT EXISTS idx_leads_outreach ON leads (outreach_status);
