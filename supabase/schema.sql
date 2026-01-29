-- =============================================
-- CIPRIAN NFC - Supabase Schema
-- =============================================
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================
-- TABLES
-- =============================================

-- Organizations (for multi-tenant support)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- NFC Tags
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    uid TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'Unnamed Tag',
    description TEXT,
    base_url TEXT NOT NULL,

    -- Keys (stored as hex strings)
    app_master_key TEXT NOT NULL,
    sdm_meta_read_key TEXT NOT NULL,
    sdm_file_read_key TEXT NOT NULL,

    -- Counter tracking (anti-replay)
    last_counter INTEGER DEFAULT 0,

    -- Stats
    scan_count INTEGER DEFAULT 0,
    last_scan_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(organization_id, uid)
);

-- Scan logs
CREATE TABLE scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tag_id UUID REFERENCES tags(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    counter INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    valid BOOLEAN NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================
-- INDEXES
-- =============================================

CREATE INDEX idx_tags_uid ON tags(uid);
CREATE INDEX idx_tags_org ON tags(organization_id);
CREATE INDEX idx_scan_logs_tag ON scan_logs(tag_id);
CREATE INDEX idx_scan_logs_created ON scan_logs(created_at DESC);

-- =============================================
-- ROW LEVEL SECURITY (RLS)
-- =============================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

-- Organizations: only accessible via service role or matching API key
CREATE POLICY "Organizations are viewable by API key" ON organizations
    FOR SELECT USING (true);  -- We'll verify API key in the app/function

-- Tags: accessible by organization
CREATE POLICY "Tags are viewable by organization" ON tags
    FOR SELECT USING (true);

CREATE POLICY "Tags are insertable by organization" ON tags
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Tags are updatable by organization" ON tags
    FOR UPDATE USING (true);

CREATE POLICY "Tags are deletable by organization" ON tags
    FOR DELETE USING (true);

-- Scan logs: accessible by organization
CREATE POLICY "Scan logs are viewable by organization" ON scan_logs
    FOR SELECT USING (true);

CREATE POLICY "Scan logs are insertable" ON scan_logs
    FOR INSERT WITH CHECK (true);

-- =============================================
-- FUNCTIONS
-- =============================================

-- Function to verify API key and get organization
CREATE OR REPLACE FUNCTION get_organization_by_api_key(p_api_key TEXT)
RETURNS UUID AS $$
DECLARE
    v_org_id UUID;
BEGIN
    SELECT id INTO v_org_id
    FROM organizations
    WHERE api_key = p_api_key;

    RETURN v_org_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to register a new tag
CREATE OR REPLACE FUNCTION register_tag(
    p_api_key TEXT,
    p_uid TEXT,
    p_name TEXT,
    p_description TEXT,
    p_base_url TEXT,
    p_app_master_key TEXT,
    p_sdm_meta_read_key TEXT,
    p_sdm_file_read_key TEXT
)
RETURNS JSON AS $$
DECLARE
    v_org_id UUID;
    v_tag_id UUID;
BEGIN
    -- Get organization
    v_org_id := get_organization_by_api_key(p_api_key);

    IF v_org_id IS NULL THEN
        RETURN json_build_object('success', false, 'error', 'Invalid API key');
    END IF;

    -- Insert tag
    INSERT INTO tags (
        organization_id, uid, name, description, base_url,
        app_master_key, sdm_meta_read_key, sdm_file_read_key
    ) VALUES (
        v_org_id, UPPER(p_uid), COALESCE(p_name, 'Unnamed Tag'), p_description, p_base_url,
        p_app_master_key, p_sdm_meta_read_key, p_sdm_file_read_key
    )
    RETURNING id INTO v_tag_id;

    RETURN json_build_object(
        'success', true,
        'tag_id', v_tag_id,
        'message', 'Tag registered successfully'
    );

EXCEPTION WHEN unique_violation THEN
    RETURN json_build_object('success', false, 'error', 'Tag with this UID already exists');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get tags for an organization
CREATE OR REPLACE FUNCTION get_tags(p_api_key TEXT)
RETURNS JSON AS $$
DECLARE
    v_org_id UUID;
    v_tags JSON;
BEGIN
    v_org_id := get_organization_by_api_key(p_api_key);

    IF v_org_id IS NULL THEN
        RETURN json_build_object('success', false, 'error', 'Invalid API key');
    END IF;

    SELECT json_agg(json_build_object(
        'id', id,
        'uid', uid,
        'name', name,
        'description', description,
        'baseUrl', base_url,
        'scanCount', scan_count,
        'lastScan', last_scan_at,
        'createdAt', created_at
    ) ORDER BY created_at DESC)
    INTO v_tags
    FROM tags
    WHERE organization_id = v_org_id;

    RETURN json_build_object(
        'success', true,
        'tags', COALESCE(v_tags, '[]'::json),
        'total', (SELECT COUNT(*) FROM tags WHERE organization_id = v_org_id)
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to update tag counter after successful scan
CREATE OR REPLACE FUNCTION update_tag_scan(
    p_tag_id UUID,
    p_counter INTEGER
)
RETURNS VOID AS $$
BEGIN
    UPDATE tags
    SET
        last_counter = p_counter,
        scan_count = scan_count + 1,
        last_scan_at = NOW(),
        updated_at = NOW()
    WHERE id = p_tag_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to log a scan
CREATE OR REPLACE FUNCTION log_scan(
    p_tag_id UUID,
    p_org_id UUID,
    p_counter INTEGER,
    p_ip TEXT,
    p_user_agent TEXT,
    p_valid BOOLEAN,
    p_failure_reason TEXT DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO scan_logs (tag_id, organization_id, counter, ip_address, user_agent, valid, failure_reason)
    VALUES (p_tag_id, p_org_id, p_counter, p_ip, p_user_agent, p_valid, p_failure_reason);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================
-- INITIAL DATA (Optional - create your org)
-- =============================================

-- Uncomment and modify to create your first organization:
-- INSERT INTO organizations (name, api_key)
-- VALUES ('My Organization', 'cpn_your_secret_api_key_here');
