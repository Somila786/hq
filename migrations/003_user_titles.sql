-- Migration 003 — job titles on accounts
--
--   npx wrangler d1 execute catalyst7-kpi --remote --file=./migrations/003_user_titles.sql
--
-- `title` is a display label only ("CEO / Co-Founder", "Head of Design").
-- Access is still decided entirely by `role` (founder | freelancer). Keeping
-- the two apart on purpose: titles change often and get edited casually, and
-- nothing that governs permissions should be that easy to change.
--
-- Safe to re-run except for the ALTER, which will report a duplicate column.

ALTER TABLE users ADD COLUMN title TEXT;

-- Invite codes can carry the title the account will be created with, so a
-- founder sets it once when issuing the code rather than fixing it afterwards.
ALTER TABLE invite_codes ADD COLUMN title TEXT;
