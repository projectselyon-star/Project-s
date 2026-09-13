-- Enhanced Security Schema for Project Selyon
-- All sensitive data fields are encrypted

-- 1. جدول الوكلاء (Agents) - محسّن
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(100) NOT NULL,
    permissions JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    
    -- Security enhancements
    api_keys_encrypted BYTEA,
    api_key_iv BYTEA,
    last_key_rotation TIMESTAMP WITH TIME ZONE,
    password_hash VARCHAR(256),
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret_encrypted BYTEA,
    mfa_secret_iv BYTEA,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID,
    updated_by UUID
);

CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_agent_code ON agents(agent_code);

-- 2. جدول الخزينة والمعاملات (Treasury Ledger) - محسّن
CREATE TABLE IF NOT EXISTS treasury_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_type VARCHAR(20) CHECK (transaction_type IN ('INCOME', 'EXPENSE', 'FEE')),
    amount NUMERIC(18, 6) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USDC',
    network VARCHAR(20) DEFAULT 'SOLANA',
    
    -- Encrypted wallet information
    solana_wallet_encrypted VARCHAR(500),
    solana_wallet_iv BYTEA,
    
    net_profit NUMERIC(18, 6),
    description TEXT,
    
    -- Encrypted sensitive details
    encrypted_details BYTEA,
    details_iv BYTEA,
    
    -- Audit trail
    created_by UUID REFERENCES agents(id),
    verified_by UUID REFERENCES agents(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_treasury_type ON treasury_ledger(transaction_type);
CREATE INDEX idx_treasury_created_at ON treasury_ledger(created_at);
CREATE INDEX idx_treasury_created_by ON treasury_ledger(created_by);

-- 3. جدول الفرص والمزادات (Opportunities)
CREATE TABLE IF NOT EXISTS opportunities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    source_trust_score NUMERIC(3, 2) CHECK (source_trust_score BETWEEN 0 AND 1),
    estimated_revenue NUMERIC(18, 2),
    estimated_cost NUMERIC(18, 2),
    profit_margin NUMERIC(5, 2),
    status VARCHAR(50) DEFAULT 'ANALYZING',
    
    -- Risk assessment
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    requires_approval BOOLEAN DEFAULT true,
    
    created_by UUID REFERENCES agents(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_opportunities_status ON opportunities(status);
CREATE INDEX idx_opportunities_created_by ON opportunities(created_by);

-- 4. جدول مركز الموافقات (Approval Center) - محسّن
CREATE TABLE IF NOT EXISTS approval_center (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_name VARCHAR(100) NOT NULL,
    risk_level VARCHAR(20) CHECK (risk_level IN ('AUTONOMOUS', 'OWNER_APPROVAL', 'OWNER_ONLY')),
    status VARCHAR(20) DEFAULT 'PENDING',
    
    -- Encrypted approval details
    details JSONB,
    encrypted_details BYTEA,
    details_iv BYTEA,
    
    requested_by UUID REFERENCES agents(id),
    approved_by UUID REFERENCES agents(id),
    approval_notes_encrypted BYTEA,
    approval_notes_iv BYTEA,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    approved_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_approval_status ON approval_center(status);
CREATE INDEX idx_approval_risk_level ON approval_center(risk_level);
CREATE INDEX idx_approval_requested_by ON approval_center(requested_by);

-- 5. سجل الأمان والمراجعة (Audit Logs) - محسّن
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    action TEXT NOT NULL,
    payload JSONB,
    
    -- Security fields
    ip_address INET,
    user_agent VARCHAR(500),
    action_status VARCHAR(20),
    risk_score NUMERIC(3, 2),
    requires_review BOOLEAN DEFAULT false,
    
    -- Indexing for performance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_agent_id ON audit_logs(agent_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_risk_score ON audit_logs(risk_score) WHERE risk_score > 0.7;

-- 6. جدول الأحداث الحساسة (Sensitive Audit Logs)
CREATE TABLE IF NOT EXISTS sensitive_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    event_type VARCHAR(100) NOT NULL,
    
    -- Encrypted event details
    encrypted_details BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    
    -- Security fields
    ip_address INET,
    user_agent VARCHAR(500),
    
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sensitive_audit_agent ON sensitive_audit_logs(agent_id);
CREATE INDEX idx_sensitive_audit_event_type ON sensitive_audit_logs(event_type);
CREATE INDEX idx_sensitive_audit_timestamp ON sensitive_audit_logs(timestamp);

-- 7. جدول التصاريح المفصلة (Agent Permissions)
CREATE TABLE IF NOT EXISTS agent_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    permission_level VARCHAR(20) CHECK (permission_level IN ('VIEW', 'EDIT', 'DELETE', 'APPROVE')),
    
    -- Expiration and conditions
    expires_at TIMESTAMP WITH TIME ZONE,
    requires_mfa BOOLEAN DEFAULT false,
    
    granted_by UUID REFERENCES agents(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(agent_id, resource, action)
);

CREATE INDEX idx_agent_perms_agent ON agent_permissions(agent_id);
CREATE INDEX idx_agent_perms_resource ON agent_permissions(resource);

-- 8. جدول التصاريح الحساسة (Sensitive Permissions)
CREATE TABLE IF NOT EXISTS sensitive_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    permission_type VARCHAR(100) NOT NULL,
    requires_mfa BOOLEAN DEFAULT true,
    requires_approval BOOLEAN DEFAULT true,
    approval_needed_from UUID REFERENCES agents(id),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_sensitive_perms_agent ON sensitive_permissions(agent_id);
CREATE INDEX idx_sensitive_perms_type ON sensitive_permissions(permission_type);

-- 9. جدول جلسات الوكلاء (Agent Sessions)
CREATE TABLE IF NOT EXISTS agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    session_token_hash VARCHAR(256) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(256),
    
    ip_address INET,
    user_agent VARCHAR(500),
    
    expires_at TIMESTAMP WITH TIME ZONE,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sessions_agent ON agent_sessions(agent_id);
CREATE INDEX idx_sessions_active ON agent_sessions(is_active);
CREATE INDEX idx_sessions_expires ON agent_sessions(expires_at);

-- 10. جدول محاولات تسجيل الدخول الفاشلة (Failed Login Attempts)
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_code VARCHAR(50),
    ip_address INET,
    reason VARCHAR(255),
    attempt_count INTEGER DEFAULT 1,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_failed_login_agent ON failed_login_attempts(agent_code);
CREATE INDEX idx_failed_login_ip ON failed_login_attempts(ip_address);
CREATE INDEX idx_failed_login_locked ON failed_login_attempts(locked_until);

-- 11. جدول مفاتيح التشفير (Encryption Keys Audit)
CREATE TABLE IF NOT EXISTS encryption_keys_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id VARCHAR(100) NOT NULL,
    key_version INTEGER,
    algorithm VARCHAR(50),
    status VARCHAR(20) CHECK (status IN ('ACTIVE', 'ROTATED', 'RETIRED')),
    
    rotated_by UUID REFERENCES agents(id),
    rotation_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    next_rotation_date TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_encryption_keys_status ON encryption_keys_audit(status);
CREATE INDEX idx_encryption_keys_rotation ON encryption_keys_audit(rotation_date);

-- Function for updating timestamps
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for agents table
CREATE TRIGGER update_agents_updated_at
BEFORE UPDATE ON agents
FOR EACH ROW
EXECUTE FUNCTION update_updated_at();

-- Row-level security can be added here for additional protection
-- ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE treasury_ledger ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE sensitive_audit_logs ENABLE ROW LEVEL SECURITY;
