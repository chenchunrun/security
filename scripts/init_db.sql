-- =============================================================================
-- Security Triage System - Database Initialization (Fixed)
-- =============================================================================
-- Version: 1.0 (Fixed)
-- Date: 2026-01-10
-- Fixes: Removed pg_cron extension, fixed execution order
-- =============================================================================

-- 1. Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION generate_alert_id()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.alert_id IS NULL THEN
        NEW.alert_id = 'ALT-' || TO_CHAR(NOW(), 'YYYYMMDD-HH24MISS') || '-' || substr(md5(random()::text), 1, 4);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 3. Tables
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    phone VARCHAR(20),
    password_hash VARCHAR(255) NOT NULL,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    role VARCHAR(50) DEFAULT 'analyst' CHECK (role IN ('admin', 'supervisor', 'analyst', 'viewer', 'auditor')),
    department VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id VARCHAR(100) UNIQUE NOT NULL,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL CHECK (asset_type IN ('server', 'workstation', 'network', 'mobile', 'cloud', 'application', 'database')),
    ip_address INET,
    mac_address MACADDR,
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    owner VARCHAR(100),
    location VARCHAR(255),
    criticality VARCHAR(20) DEFAULT 'medium' CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    business_unit VARCHAR(100),
    environment VARCHAR(20) DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development', 'test')),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) UNIQUE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    alert_type VARCHAR(50) NOT NULL CHECK (alert_type IN ('malware', 'phishing', 'brute_force', 'data_exfiltration', 'anomaly', 'denial_of_service', 'unauthorized_access', 'policy_violation', 'other')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title VARCHAR(500),
    description TEXT,
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    user_name VARCHAR(100),
    asset_id VARCHAR(100),
    file_hash VARCHAR(100),
    file_name VARCHAR(255),
    url VARCHAR(1000),
    dns_query VARCHAR(500),
    raw_data JSONB,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'analyzing', 'analyzed', 'investigating', 'resolved', 'false_positive', 'suppressed')),
    assigned_to VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS triage_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) UNIQUE NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level VARCHAR(20) CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    analysis_result TEXT,
    recommended_actions TEXT,
    requires_human_review BOOLEAN DEFAULT false,
    human_reviewer VARCHAR(100),
    human_review_notes TEXT,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc VARCHAR(1000) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url', 'hash', 'email', 'certificate')),
    threat_level VARCHAR(20) CHECK (threat_level IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    source VARCHAR(100),
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    detection_rate DECIMAL(5,2),
    positives INTEGER,
    total INTEGER,
    tags TEXT[],
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(ioc, ioc_type)
);

CREATE TABLE IF NOT EXISTS alert_context (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    context_type VARCHAR(50) NOT NULL CHECK (context_type IN ('network', 'asset', 'user', 'threat_intel', 'historical', 'correlation')),
    context_data JSONB NOT NULL,
    source VARCHAR(100),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'eradicated', 'resolved', 'closed')),
    assigned_to VARCHAR(100),
    detection_date TIMESTAMP WITH TIME ZONE NOT NULL,
    containment_date TIMESTAMP WITH TIME ZONE,
    eradication_date TIMESTAMP WITH TIME ZONE,
    resolution_date TIMESTAMP WITH TIME ZONE,
    root_cause TEXT,
    impact_assessment TEXT,
    lessons_learned TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(100),
    alert_id VARCHAR(100) REFERENCES alerts(alert_id) ON DELETE SET NULL,
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN ('containment', 'eradication', 'patching', 'configuration_change', 'access_revocation', 'isolation', 'other')),
    description TEXT NOT NULL,
    priority INTEGER CHECK (priority >= 1 AND priority <= 5),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'skipped', 'failed')),
    assigned_to VARCHAR(100),
    due_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id VARCHAR(100),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_triage_results_alert_id ON triage_results(alert_id);
CREATE INDEX IF NOT EXISTS idx_triage_results_risk_score ON triage_results(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc ON threat_intel(ioc);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc_type ON threat_intel(ioc_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_threat_level ON threat_intel(threat_level);
CREATE INDEX IF NOT EXISTS idx_alert_context_alert_id ON alert_context(alert_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- 5. Triggers
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_alert_id_trigger BEFORE INSERT ON alerts
    FOR EACH ROW EXECUTE FUNCTION generate_alert_id();

CREATE TRIGGER update_triage_results_updated_at BEFORE UPDATE ON triage_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_intel_updated_at BEFORE UPDATE ON threat_intel
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alert_context_updated_at BEFORE UPDATE ON alert_context
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_incidents_updated_at BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_remediation_actions_updated_at BEFORE UPDATE ON remediation_actions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 6. Insert initial data (passwords are bcrypt hashes for 'admin123' and 'analyst123')
INSERT INTO users (username, email, full_name, password_hash, role, is_active) VALUES
('admin', 'admin@security.local', 'System Administrator', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7xIXU2bq4e', 'admin', true),
('analyst', 'analyst@security.local', 'Security Analyst', '$2b$12$K2x.NHQzLJ8H9wJz5SHO1eSq6Tmw9tNSxIHIPkEB0mFNJhLyN9MLO', 'analyst', true)
ON CONFLICT (username) DO NOTHING;

INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, criticality, environment) VALUES
('SRV-001', 'Production Web Server', 'server', '10.0.1.10', 'high', 'production'),
('SRV-002', 'Database Server', 'server', '10.0.1.20', 'critical', 'production'),
('WS-001', 'HR Workstation', 'workstation', '10.0.2.50', 'medium', 'production')
ON CONFLICT (asset_id) DO NOTHING;

-- 7. Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO triage_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO triage_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO triage_user;

RAISE NOTICE 'Security Triage System database initialization completed successfully!';
RAISE NOTICE 'Default users: admin/admin123, analyst/analyst123 (CHANGE THESE IN PRODUCTION!)';
