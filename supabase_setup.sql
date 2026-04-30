-- MIH Project Tracker - Supabase Setup (Secured v2)
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- Safe to re-run (idempotent)

-- 0. Enable pgcrypto for proper password hashing
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- 1. PROJECT STATE TABLE (non-sensitive app data as JSON)
-- ============================================================
CREATE TABLE IF NOT EXISTS project_state (
  id INTEGER PRIMARY KEY DEFAULT 1,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT single_row CHECK (id = 1)
);

ALTER TABLE project_state ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "allow_select" ON project_state;
DROP POLICY IF EXISTS "allow_insert" ON project_state;
DROP POLICY IF EXISTS "allow_update" ON project_state;

CREATE POLICY "allow_select" ON project_state FOR SELECT TO anon USING (true);
CREATE POLICY "allow_insert" ON project_state FOR INSERT TO anon WITH CHECK (id = 1);
CREATE POLICY "allow_update" ON project_state FOR UPDATE TO anon
  USING (id = 1) WITH CHECK (id = 1);

-- Auto-update trigger for updated_at
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_project_state_timestamp ON project_state;
CREATE TRIGGER update_project_state_timestamp
  BEFORE UPDATE ON project_state
  FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- Seed (only on first run)
INSERT INTO project_state (id, data) VALUES (1, jsonb_build_object(
  'admin_pin_hash', crypt('1234', gen_salt('bf'))
))
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 2. MEMBERS TABLE (passwords stored as bcrypt hashes)
-- ============================================================
CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT DEFAULT '',
  tag TEXT DEFAULT '',
  pwd_hash TEXT NOT NULL DEFAULT crypt('000', gen_salt('bf')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE members ENABLE ROW LEVEL SECURITY;
-- No policies for anon = no direct table access. All access via view + RPCs.

-- Safe public view (no password column)
CREATE OR REPLACE VIEW members_public AS
  SELECT id, name, email, tag FROM members;

GRANT SELECT ON members_public TO anon;

-- ============================================================
-- 3. RPC FUNCTIONS (SECURITY DEFINER = bypasses RLS)
-- ============================================================

-- Auth: member login
CREATE OR REPLACE FUNCTION authenticate_member(identifier TEXT, pwd TEXT)
RETURNS JSON AS $$
DECLARE
  m RECORD;
BEGIN
  SELECT id, name, email, tag INTO m FROM members
  WHERE (LOWER(email) = LOWER(identifier) OR LOWER(name) = LOWER(identifier))
    AND pwd_hash = crypt(pwd, pwd_hash);
  IF m.id IS NULL THEN
    RETURN json_build_object('success', false);
  END IF;
  RETURN json_build_object('success', true, 'member', json_build_object(
    'id', m.id, 'name', m.name, 'email', m.email, 'tag', m.tag
  ));
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Auth: admin login
CREATE OR REPLACE FUNCTION authenticate_admin(pin TEXT)
RETURNS JSON AS $$
DECLARE
  stored_hash TEXT;
BEGIN
  SELECT data->>'admin_pin_hash' INTO stored_hash
  FROM project_state WHERE id = 1;
  IF stored_hash IS NOT NULL AND stored_hash = crypt(pin, stored_hash) THEN
    RETURN json_build_object('success', true);
  END IF;
  RETURN json_build_object('success', false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- CRUD: add member
CREATE OR REPLACE FUNCTION add_member(
  member_id TEXT, member_name TEXT,
  member_email TEXT DEFAULT '', member_tag TEXT DEFAULT '',
  member_pwd TEXT DEFAULT '000')
RETURNS JSON AS $$
BEGIN
  INSERT INTO members (id, name, email, tag, pwd_hash)
  VALUES (member_id, member_name, member_email, member_tag,
          crypt(member_pwd, gen_salt('bf')));
  RETURN json_build_object('success', true);
EXCEPTION WHEN unique_violation THEN
  RETURN json_build_object('success', false, 'error', 'ID exists');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- CRUD: update member info (not password)
CREATE OR REPLACE FUNCTION update_member(
  member_id TEXT, member_name TEXT,
  member_email TEXT DEFAULT '', member_tag TEXT DEFAULT '')
RETURNS JSON AS $$
BEGIN
  UPDATE members SET name=member_name, email=member_email, tag=member_tag
  WHERE id=member_id;
  RETURN json_build_object('success', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- CRUD: delete member
CREATE OR REPLACE FUNCTION delete_member(member_id TEXT)
RETURNS JSON AS $$
BEGIN
  DELETE FROM members WHERE id=member_id;
  RETURN json_build_object('success', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Password: change member password
CREATE OR REPLACE FUNCTION change_member_password(member_id TEXT, new_pwd TEXT)
RETURNS JSON AS $$
BEGIN
  UPDATE members SET pwd_hash = crypt(new_pwd, gen_salt('bf'))
  WHERE id=member_id;
  RETURN json_build_object('success', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Password: change admin PIN
CREATE OR REPLACE FUNCTION change_admin_pin(new_pin TEXT)
RETURNS JSON AS $$
BEGIN
  UPDATE project_state
  SET data = jsonb_set(
    COALESCE(data,'{}'::jsonb),
    '{admin_pin_hash}',
    to_jsonb(crypt(new_pin, gen_salt('bf')))
  )
  WHERE id = 1;
  RETURN json_build_object('success', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Migration: move members from JSON blob to members table (one-time)
CREATE OR REPLACE FUNCTION migrate_members_from_json()
RETURNS JSON AS $$
DECLARE
  member_data JSONB;
  m JSONB;
  cnt INTEGER := 0;
BEGIN
  SELECT data->'members' INTO member_data FROM project_state WHERE id = 1;
  IF member_data IS NULL OR jsonb_array_length(member_data) = 0 THEN
    RETURN json_build_object('success', true, 'migrated', 0);
  END IF;
  FOR m IN SELECT * FROM jsonb_array_elements(member_data) LOOP
    INSERT INTO members (id, name, email, tag, pwd_hash)
    VALUES (
      m->>'id', m->>'name',
      COALESCE(m->>'email',''), COALESCE(m->>'tag',''),
      crypt(COALESCE(m->>'pwd','000'), gen_salt('bf'))
    ) ON CONFLICT (id) DO NOTHING;
    cnt := cnt + 1;
  END LOOP;
  -- Remove sensitive fields from the JSON blob
  UPDATE project_state
  SET data = data - 'members' - 'pin'
  WHERE id = 1;
  RETURN json_build_object('success', true, 'migrated', cnt);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================
-- 4. FILE UPLOAD BUCKET
-- ============================================================
INSERT INTO storage.buckets (id, name, public)
VALUES ('uploads', 'uploads', true)
ON CONFLICT (id) DO NOTHING;

DROP POLICY IF EXISTS "upload_anon" ON storage.objects;
DROP POLICY IF EXISTS "read_anon"   ON storage.objects;
DROP POLICY IF EXISTS "update_anon" ON storage.objects;
DROP POLICY IF EXISTS "delete_anon" ON storage.objects;

CREATE POLICY "upload_anon" ON storage.objects FOR INSERT TO anon
  WITH CHECK (bucket_id = 'uploads');
CREATE POLICY "read_anon" ON storage.objects FOR SELECT TO anon
  USING (bucket_id = 'uploads');
CREATE POLICY "update_anon" ON storage.objects FOR UPDATE TO anon
  USING (bucket_id = 'uploads');
CREATE POLICY "delete_anon" ON storage.objects FOR DELETE TO anon
  USING (bucket_id = 'uploads');
