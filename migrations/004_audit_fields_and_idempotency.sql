-- Migration 004 — C7 web app standard remediation
--
--   npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/004_audit_fields_and_idempotency.sql
--
-- Two things the C7 standard requires that were missing:
--
-- 1. audit_log needs `ip_address` and `status`. Without them you can see who
--    did what, but not from where, or whether it actually succeeded -- which
--    is most of what an incident investigation needs (POPIA §17).
--
-- 2. Idempotency for form submissions. Every mutating form now carries a
--    one-time nonce; the first POST claims it, later duplicates find it taken
--    and are redirected without re-running the business logic. This is what
--    stops a double-clicked "Add entry" creating two revenue rows.

ALTER TABLE audit_log ADD COLUMN ip_address TEXT;
ALTER TABLE audit_log ADD COLUMN status TEXT DEFAULT 'success';

-- One row per accepted submission, not per rendered form -- rendering costs
-- nothing. PRIMARY KEY does the deduplication: the second INSERT of the same
-- nonce simply fails, which is the signal that it's a repeat.
CREATE TABLE IF NOT EXISTS submissions (
  nonce TEXT PRIMARY KEY,
  used_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_submissions_age ON submissions (used_at);
