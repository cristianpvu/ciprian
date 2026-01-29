-- =============================================
-- CIPRIAN NFC - Schema pentru Backend Node.js
-- =============================================
-- Rulează asta în Supabase SQL Editor
-- ATENȚIE: Șterge tabelele vechi mai întâi dacă există!

-- Șterge tabelele vechi (dacă există)
DROP TABLE IF EXISTS scan_logs CASCADE;
DROP TABLE IF EXISTS tags CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Șterge funcțiile vechi
DROP FUNCTION IF EXISTS get_organization_by_api_key CASCADE;
DROP FUNCTION IF EXISTS register_tag CASCADE;
DROP FUNCTION IF EXISTS get_tags CASCADE;
DROP FUNCTION IF EXISTS update_tag_scan CASCADE;
DROP FUNCTION IF EXISTS log_scan CASCADE;

-- =============================================
-- TABELE NOI
-- =============================================

-- Users (utilizatorii aplicației)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tags (cipurile NFC programate)
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    uid TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT 'Unnamed Tag',
    description TEXT,
    base_url TEXT NOT NULL,

    -- Chei (stocate ca hex strings)
    app_master_key TEXT NOT NULL,
    sdm_meta_read_key TEXT NOT NULL,
    sdm_file_read_key TEXT NOT NULL,

    -- Counter pentru anti-replay
    last_counter INTEGER DEFAULT 0,

    -- Statistici
    scan_count INTEGER DEFAULT 0,
    last_scan_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan logs (istoricul scanărilor)
CREATE TABLE scan_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tag_id UUID REFERENCES tags(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    ip_address TEXT,
    user_agent TEXT,
    valid BOOLEAN NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================
-- INDEXES
-- =============================================

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_tags_uid ON tags(uid);
CREATE INDEX idx_tags_user ON tags(user_id);
CREATE INDEX idx_scan_logs_tag ON scan_logs(tag_id);
CREATE INDEX idx_scan_logs_created ON scan_logs(created_at DESC);

-- =============================================
-- ROW LEVEL SECURITY (RLS) - Dezactivat
-- Backend-ul nostru folosește service_role key
-- =============================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

-- Politici permisive (backend-ul are acces total cu service_role)
CREATE POLICY "Service role full access" ON users FOR ALL USING (true);
CREATE POLICY "Service role full access" ON tags FOR ALL USING (true);
CREATE POLICY "Service role full access" ON scan_logs FOR ALL USING (true);

-- =============================================
-- DONE!
-- =============================================
