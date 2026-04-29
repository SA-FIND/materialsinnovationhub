-- MIH Project Tracker - Supabase Setup
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)

-- 1. Project state table (stores all app data as JSON)
CREATE TABLE IF NOT EXISTS project_state (
  id INTEGER PRIMARY KEY DEFAULT 1,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT single_row CHECK (id = 1)
);

-- 2. Row Level Security policies
ALTER TABLE project_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_select" ON project_state FOR SELECT TO anon USING (true);
CREATE POLICY "allow_insert" ON project_state FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "allow_update" ON project_state FOR UPDATE TO anon USING (true);

-- 3. Seed initial row
INSERT INTO project_state (id, data) VALUES (1, '{}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- 4. File upload bucket
INSERT INTO storage.buckets (id, name, public) VALUES ('uploads', 'uploads', true)
ON CONFLICT (id) DO NOTHING;

-- 5. Storage policies
CREATE POLICY "upload_anon" ON storage.objects FOR INSERT TO anon WITH CHECK (bucket_id = 'uploads');
CREATE POLICY "read_anon" ON storage.objects FOR SELECT TO anon USING (bucket_id = 'uploads');
CREATE POLICY "update_anon" ON storage.objects FOR UPDATE TO anon USING (bucket_id = 'uploads');
CREATE POLICY "delete_anon" ON storage.objects FOR DELETE TO anon USING (bucket_id = 'uploads');
