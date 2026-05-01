-- ========================================================================================
-- PHASE 1: WIPE THE SLATE CLEAN
-- ========================================================================================
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;

DROP TABLE IF EXISTS attendance_records CASCADE;
DROP TABLE IF EXISTS task_assignees CASCADE;
DROP TABLE IF EXISTS tasks CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS phases CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS project_overview CASCADE;
DROP TABLE IF EXISTS members CASCADE;
DROP TABLE IF EXISTS project_state CASCADE;
DROP VIEW IF EXISTS members_public CASCADE;

DROP FUNCTION IF EXISTS authenticate_member CASCADE;
DROP FUNCTION IF EXISTS authenticate_admin CASCADE;
DROP FUNCTION IF EXISTS add_member CASCADE;
DROP FUNCTION IF EXISTS update_member CASCADE;
DROP FUNCTION IF EXISTS delete_member CASCADE;
DROP FUNCTION IF EXISTS change_member_password CASCADE;
DROP FUNCTION IF EXISTS change_admin_pin CASCADE;

-- ========================================================================================
-- PHASE 2: REBUILD TABLES
-- ========================================================================================
CREATE TABLE members (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  tag TEXT,
  role TEXT DEFAULT 'member' CHECK (role IN ('member', 'admin')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE project_overview (
  id INT PRIMARY KEY DEFAULT 1,
  content TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT single_row CHECK (id = 1)
);

INSERT INTO project_overview (id, content) VALUES (1, 'Welcome to the MIH Tracker.');

CREATE TABLE phases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  locked BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phase_id UUID REFERENCES phases(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in progress', 'done')),
  file_url TEXT,
  file_name TEXT,
  references_text TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE task_assignees (
  task_id UUID REFERENCES tasks(id) ON DELETE CASCADE,
  member_id UUID REFERENCES members(id) ON DELETE CASCADE,
  PRIMARY KEY (task_id, member_id)
);

CREATE TABLE reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_type TEXT NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in progress', 'done')),
  file_url TEXT,
  file_name TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  label TEXT NOT NULL,
  active BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE attendance_records (
  session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
  member_id UUID REFERENCES members(id) ON DELETE CASCADE,
  status TEXT CHECK (status IN ('present', 'absent', 'none')),
  PRIMARY KEY (session_id, member_id)
);

-- ========================================================================================
-- PHASE 3: AUTOMATED AUTHENTICATION TRIGGER
-- ========================================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.members (id, name, email, tag)
  VALUES (
    new.id,
    COALESCE(new.raw_user_meta_data->>'name', 'New Member'), 
    new.email,
    new.raw_user_meta_data->>'tag'
  );
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- ========================================================================================
-- PHASE 4: SECURE POLICIES
-- ========================================================================================
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_overview ENABLE ROW LEVEL SECURITY;
ALTER TABLE phases ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_assignees ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Auth users can view members" ON members FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view overview" ON project_overview FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view phases" ON phases FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view tasks" ON tasks FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view assignees" ON task_assignees FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view reports" ON reports FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view sessions" ON sessions FOR SELECT TO authenticated USING (true);
CREATE POLICY "Auth users can view attendance" ON attendance_records FOR SELECT TO authenticated USING (true);

CREATE POLICY "Users can update own profile" ON members FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());
CREATE POLICY "Admins update overview" ON project_overview FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins manage phases" ON phases FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins manage tasks" ON tasks FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Assignees can update their tasks" ON tasks FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM task_assignees WHERE task_id = tasks.id AND member_id = auth.uid()));
CREATE POLICY "Admins manage task assignees" ON task_assignees FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Auth users can update reports" ON reports FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Admins manage reports" ON reports FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins delete reports" ON reports FOR DELETE TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins manage sessions" ON sessions FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins manage all attendance" ON attendance_records FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM members WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Members log own attendance" ON attendance_records FOR INSERT TO authenticated WITH CHECK (member_id = auth.uid());
CREATE POLICY "Members update own attendance" ON attendance_records FOR UPDATE TO authenticated USING (member_id = auth.uid()) WITH CHECK (member_id = auth.uid());

INSERT INTO storage.buckets (id, name, public) VALUES ('uploads', 'uploads', true) ON CONFLICT (id) DO NOTHING;
DROP POLICY IF EXISTS "Public read uploads" ON storage.objects;
DROP POLICY IF EXISTS "Auth users upload files" ON storage.objects;
DROP POLICY IF EXISTS "Auth users update files" ON storage.objects;
DROP POLICY IF EXISTS "Only admins delete files" ON storage.objects;

CREATE POLICY "Public read uploads" ON storage.objects FOR SELECT TO public USING (bucket_id = 'uploads');
CREATE POLICY "Auth users upload files" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'uploads');
CREATE POLICY "Auth users update files" ON storage.objects FOR UPDATE TO authenticated USING (bucket_id = 'uploads');
CREATE POLICY "Only admins delete files" ON storage.objects FOR DELETE TO authenticated USING (bucket_id = 'uploads' AND EXISTS (SELECT 1 FROM public.members WHERE id = auth.uid() AND role = 'admin'));