-- Migration 009 -- the email draft, held on the lead (CRM step 4)
--
--   Run in the D1 console, or via the Cloudflare MCP d1_database_query tool.
--
-- Until now a founder approved a lead without ever seeing the email that would
-- go out: the copy lived in the Make payload, and HQ had no field for it. That
-- makes the approval gate weaker than it looks -- you are authorising a send
-- whose contents you have not read.
--
-- The draft now lives on the lead. Claude writes it when it qualifies, a
-- founder reads and edits it before approving, and HQ hands it to Make at send.
--
-- The GREETING IS DELIBERATELY NOT STORED. The house rule is that it must match
-- the clock time of the SEND, not of the drafting -- a lead drafted at 10:00 and
-- approved at 18:00 must not go out saying "Good morning". The body keeps a
-- {{greeting}} placeholder and HQ substitutes it at the moment it triggers the
-- send, in SAST.

ALTER TABLE leads ADD COLUMN email_subject TEXT;
ALTER TABLE leads ADD COLUMN email_body TEXT;
ALTER TABLE leads ADD COLUMN drafted_at TEXT;
ALTER TABLE leads ADD COLUMN drafted_by TEXT;
