-- ============================================================
-- MIH Project Tracker — Supabase Setup
-- Run this entire script in the Supabase SQL Editor:
--   Dashboard → SQL Editor → New query → paste → Run
-- ============================================================

-- 1. Create the app_state table (stores the full app state as JSONB)
CREATE TABLE IF NOT EXISTS public.app_state (
  id TEXT PRIMARY KEY,
  state JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Row-Level Security
--    The app manages its own PIN-based authentication, so we allow
--    anonymous reads and writes here. The anon key is safe to expose
--    in the client because data sensitivity is managed by the app layer.
ALTER TABLE public.app_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "anon_select" ON public.app_state
  FOR SELECT TO anon USING (true);

CREATE POLICY "anon_insert" ON public.app_state
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "anon_update" ON public.app_state
  FOR UPDATE TO anon USING (true) WITH CHECK (true);

-- ============================================================
-- 3. Storage bucket for task and report file uploads
--    Run these statements AFTER creating the bucket manually:
--      Dashboard → Storage → New bucket → Name: mih-files → Private → Create
--    Then run the policies below.
-- ============================================================

CREATE POLICY "anon_upload" ON storage.objects
  FOR INSERT TO anon
  WITH CHECK (bucket_id = 'mih-files');

CREATE POLICY "anon_select" ON storage.objects
  FOR SELECT TO anon
  USING (bucket_id = 'mih-files');

CREATE POLICY "anon_update" ON storage.objects
  FOR UPDATE TO anon
  USING (bucket_id = 'mih-files');
