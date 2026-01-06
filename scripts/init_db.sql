-- Copyright 2026 CCR <chenchunrun@gmail.com>
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

 =============================================================================
-- Security Triage System - Database Initialization Script
 --
-- This script creates all required tables, indexes, and initial data
-- for the security alert triage system.
-- =============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- Alerts Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS alerts (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Core fields (required)
    alert_id VARCHAR(100) NOT NULL UNIQUE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,

    -- Network information (optional)
    source_ip INET,
    target_ip INET,

    -- Entity references (optional)
    asset_id VARCHAR(100),
    user_id VARCHAR(255),

    -- Threat-specific fields (optional)
    file_hash VARCHAR(64),
    url TEXT,

    -- Metadata (JSONB for flexibility)
    raw_data JSONB,
    normalized_data JSONB,

    -- Processing metadata
    status VARCHAR(50) DEFAULT 'new',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT alert_type_check CHECK (alert_type IN (
        'malware', 'phishing', 'brute_force', 'ddos',
        'data_exfiltration', 'unauthorized_access', 'anomaly', 'other'
    )),
    CONSTRAINT severity_check CHECK (severity IN (
        'critical', 'high', 'medium', 'low', 'info'
    )),
    CONSTRAINT status_check CHECK (status IN (
        'new', 'assigned', 'in_progress', 'pending_review', 'resolved', 'closed'
    ))
);

-- Indexes for alerts table
CREATE INDEX idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_alert_type ON alerts(alert_type);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX idx_alerts_target_ip ON alerts(target_ip) WHERE target_ip IS NOT NULL;
CREATE INDEX idx_alerts_asset_id ON alerts(asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX idx_alerts_user_id ON alerts(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_alerts_file_hash ON alerts(file_hash) WHERE file_hash IS NOT NULL;
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

-- GIN index for JSONB fields
CREATE INDEX idx_alerts_raw_data ON alerts USING GIN(raw_data);
CREATE INDEX idx_alerts_normalized_data ON alerts USING GIN(normalized_data);

-- =============================================================================
-- Triage Results Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS triage_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) NOT NULL UNIQUE REFERENCES alerts(alert_id) ON DELETE CASCADE,

    -- Risk assessment
    risk_score DECIMAL(5,2),
    risk_level VARCHAR(20),
    confidence DECIMAL(5,2),

    -- Score components
    severity_score DECIMAL(5,2),
    threat_intel_score DECIMAL(5,2),
    asset_criticality_score DECIMAL(5,2),
    exploitability_score DECIMAL(5,2),

    -- Key factors (JSONB array)
    key_factors JSONB,

    -- Human review
    requires_human_review BOOLEAN DEFAULT FALSE,
    human_review_assigned_to VARCHAR(255),
    human_review_completed_at TIMESTAMP WITH TIME ZONE,
    human_review_notes TEXT,

    -- Metadata
    processing_time_seconds DECIMAL(10,3),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT risk_level_check CHECK (risk_level IN (
        'critical', 'high', 'medium', 'low', 'info'
    ))
);

-- Indexes for triage_results
CREATE INDEX idx_triage_alert_id ON triage_results(alert_id);
CREATE INDEX idx_triage_risk_score ON triage_results(risk_score DESC);
CREATE INDEX idx_triage_risk_level ON triage_results(risk_level);
CREATE INDEX idx_triage_requires_review ON triage_results(requires_human_review) WHERE requires_human_review = TRUE;
CREATE INDEX idx_triage_created_at ON triage_results(created_at DESC);

-- =============================================================================
-- Remediation Actions Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS remediation_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,

    -- Action details
    action_type VARCHAR(100) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,

    -- Execution
    is_automated BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'pending',
    assigned_to VARCHAR(255),
    completed_at TIMESTAMP WITH TIME ZONE,
    execution_result JSONB,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT priority_check CHECK (priority IN (
        'immediate', 'high', 'medium', 'low'
    )),
    CONSTRAINT action_status_check CHECK (status IN (
        'pending', 'in_progress', 'completed', 'failed', 'skipped'
    ))
);

-- Indexes for remediation_actions
CREATE INDEX idx_remediation_alert_id ON remediation_actions(alert_id);
CREATE INDEX idx_remediation_priority ON remediation_actions(priority);
CREATE INDEX idx_remediation_status ON remediation_actions(status);
CREATE INDEX idx_remediation_is_automated ON remediation_actions(is_automated);
CREATE INDEX idx_remediation_created_at ON remediation_actions(created_at DESC);

-- =============================================================================
-- Threat Intelligence Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- IOC details
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value TEXT NOT NULL,

    -- Threat assessment
    threat_level VARCHAR(20),
    threat_score DECIMAL(5,2),

    -- Source information
    source VARCHAR(100),
    source_url TEXT,
    last_seen TIMESTAMP WITH TIME ZONE,

    -- Metadata (JSONB for flexible source-specific data)
    source_data JSONB,

    -- Cache management
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT threat_level_check CHECK (threat_level IN (
        'critical', 'high', 'medium', 'low', 'unknown'
    )),
    UNIQUE(ioc_type, ioc_value)
);

-- Indexes for threat_intelligence
CREATE INDEX idx_threat_ioc_type ON threat_intelligence(ioc_type);
CREATE INDEX idx_threat_ioc_value ON threat_intelligence(ioc_value);
CREATE INDEX idx_threat_threat_level ON threat_intelligence(threat_level);
CREATE INDEX idx_threat_threat_score ON threat_intelligence(threat_score DESC);
CREATE INDEX idx_threat_expires_at ON threat_intelligence(expires_at) WHERE expires_at IS NOT NULL;

-- =============================================================================
-- Context Information Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS context_info (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,

    -- Context data (JSONB for flexibility)
    network_context JSONB,
    asset_context JSONB,
    user_context JSONB,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Cache management
    expires_at TIMESTAMP WITH TIME ZONE,

    UNIQUE(entity_type, entity_id)
);

-- Indexes for context_info
CREATE INDEX idx_context_entity ON context_info(entity_type, entity_id);
CREATE INDEX idx_context_expires_at ON context_info(expires_at) WHERE expires_at IS NOT NULL;

-- =============================================================================
-- Audit Log Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Event details
    event_type VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id VARCHAR(255),

    -- Change tracking
    old_value JSONB,
    new_value JSONB,

    -- User tracking
    performed_by VARCHAR(255),
    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    ip_address INET,
    user_agent TEXT,
    additional_data JSONB
);

-- Indexes for audit_logs
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX idx_audit_performed_by ON audit_logs(performed_by);
CREATE INDEX idx_audit_performed_at ON audit_logs(performed_at DESC);

-- =============================================================================
-- Functions and Triggers
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_triage_results_updated_at
    BEFORE UPDATE ON triage_results
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_remediation_actions_updated_at
    BEFORE UPDATE ON remediation_actions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_intelligence_updated_at
    BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_context_info_updated_at
    BEFORE UPDATE ON context_info
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Sample Data (Optional - for testing)
-- =============================================================================

-- Insert sample alerts (can be removed in production)
INSERT INTO alerts (alert_id, timestamp, alert_type, severity, description, source_ip, target_ip)
VALUES
    ('ALT-2025-001', '2025-01-05 12:00:00+00', 'malware', 'high', 'Detected suspicious file execution on endpoint', '45.33.32.156', '10.0.0.50'),
    ('ALT-2025-002', '2025-01-05 11:30:00+00', 'brute_force', 'medium', 'Multiple failed login attempts detected', '192.168.1.200', '10.0.0.10'),
    ('ALT-2025-003', '2025-01-05 10:15:00+00', 'anomaly', 'low', 'Unusual network traffic pattern detected', '10.0.1.50', '10.0.0.100'),
    ('ALT-2025-004', '2025-01-05 09:45:00+00', 'data_exfiltration', 'critical', 'Large data transfer to external IP detected', '10.0.0.75', '203.0.113.45')
ON CONFLICT (alert_id) DO NOTHING;

-- =============================================================================
-- Grant Permissions (adjust as needed)
-- =============================================================================

-- Grant usage on schema
-- GRANT USAGE ON SCHEMA public TO triage_user;

-- Grant permissions on tables
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO triage_user;

-- Grant usage on sequences
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO triage_user;

 =============================================================================
-- Database Initialization Complete
-- =============================================================================

-- Log completion
DO $$
BEGIN
    RAISE NOTICE 'Security Triage System database initialization completed successfully!';
END $$;
