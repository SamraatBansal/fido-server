# FIDO2/WebAuthn Server - Database Schema

## Overview

This document provides the complete database schema for the FIDO2/WebAuthn Relying Party Server, including table definitions, constraints, indexes, and migration scripts for PostgreSQL.

## 1. Database Schema

### 1.1 Users Table

```sql
-- Users table for storing user account information
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255), -- Optional for password fallback
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_is_active ON users(is_active);

-- Constraints
ALTER TABLE users ADD CONSTRAINT chk_users_username_length 
    CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 255);
ALTER TABLE users ADD CONSTRAINT chk_users_display_name_length 
    CHECK (LENGTH(display_name) >= 1 AND LENGTH(display_name) <= 255);
ALTER TABLE users ADD CONSTRAINT chk_users_email_format 
    CHECK (email IS NULL OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
```

### 1.2 Credentials Table

```sql
-- Credentials table for storing WebAuthn credentials
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_id_base64 VARCHAR(1024) UNIQUE NOT NULL, -- Base64URL encoded for easier querying
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    backup_eligible BOOLEAN DEFAULT false,
    backed_up BOOLEAN DEFAULT false,
    is_resident BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    device_type VARCHAR(50), -- 'single_device', 'multi_device'
    user_verification VARCHAR(20) DEFAULT 'preferred', -- 'required', 'preferred', 'discouraged'
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_credential_id_base64 ON credentials(credential_id_base64);
CREATE INDEX idx_credentials_created_at ON credentials(created_at);
CREATE INDEX idx_credentials_last_used_at ON credentials(last_used_at);
CREATE INDEX idx_credentials_is_active ON credentials(is_active);
CREATE INDEX idx_credentials_attestation_type ON credentials(attestation_type);

-- Constraints
ALTER TABLE credentials ADD CONSTRAINT chk_credentials_sign_count 
    CHECK (sign_count >= 0);
ALTER TABLE credentials ADD CONSTRAINT chk_credentials_attestation_type 
    CHECK (attestation_type IN ('packed', 'fido-u2f', 'none', 'android-key', 'android-safetynet', 'apple', 'tpm'));
ALTER TABLE credentials ADD CONSTRAINT chk_credentials_user_verification 
    CHECK (user_verification IN ('required', 'preferred', 'discouraged'));
ALTER TABLE credentials ADD CONSTRAINT chk_credentials_device_type 
    CHECK (device_type IS NULL OR device_type IN ('single_device', 'multi_device'));
```

### 1.3 Challenges Table

```sql
-- Challenges table for storing one-time challenges
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    challenge_base64 VARCHAR(1024) UNIQUE NOT NULL, -- Base64URL encoded
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255), -- For anonymous sessions
    challenge_type VARCHAR(20) NOT NULL, -- 'registration', 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    client_data JSONB, -- Store client data for debugging
    ip_address INET,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_challenges_challenge ON challenges(challenge);
CREATE INDEX idx_challenges_challenge_base64 ON challenges(challenge_base64);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_session_id ON challenges(session_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_is_used ON challenges(is_used);
CREATE INDEX idx_challenges_challenge_type ON challenges(challenge_type);

-- Constraints
ALTER TABLE challenges ADD CONSTRAINT chk_challenges_type 
    CHECK (challenge_type IN ('registration', 'authentication'));
ALTER TABLE challenges ADD CONSTRAINT chk_challenges_expiration 
    CHECK (expires_at > created_at);
```

### 1.4 Sessions Table

```sql
-- Sessions table for managing user sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    device_fingerprint VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_session_token ON sessions(session_token);
CREATE INDEX idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_last_accessed_at ON sessions(last_accessed_at);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);
CREATE INDEX idx_sessions_device_fingerprint ON sessions(device_fingerprint);

-- Constraints
ALTER TABLE sessions ADD CONSTRAINT chk_sessions_expiration 
    CHECK (expires_at > created_at);
```

### 1.5 Authentication Attempts Table

```sql
-- Authentication attempts for security monitoring
CREATE TABLE authentication_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    credential_id BYTEA,
    attempt_type VARCHAR(20) NOT NULL, -- 'registration', 'authentication'
    status VARCHAR(20) NOT NULL, -- 'success', 'failure', 'blocked'
    failure_reason VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    session_id VARCHAR(255),
    challenge_id UUID REFERENCES challenges(id) ON DELETE SET NULL,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_auth_attempts_username ON authentication_attempts(username);
CREATE INDEX idx_auth_attempts_user_id ON authentication_attempts(user_id);
CREATE INDEX idx_auth_attempts_credential_id ON authentication_attempts(credential_id);
CREATE INDEX idx_auth_attempts_attempt_type ON authentication_attempts(attempt_type);
CREATE INDEX idx_auth_attempts_status ON authentication_attempts(status);
CREATE INDEX idx_auth_attempts_created_at ON authentication_attempts(created_at);
CREATE INDEX idx_auth_attempts_ip_address ON authentication_attempts(ip_address);

-- Constraints
ALTER TABLE authentication_attempts ADD CONSTRAINT chk_auth_attempt_type 
    CHECK (attempt_type IN ('registration', 'authentication'));
ALTER TABLE authentication_attempts ADD CONSTRAINT chk_auth_status 
    CHECK (status IN ('success', 'failure', 'blocked'));
```

### 1.6 Rate Limits Table

```sql
-- Rate limits for API endpoints
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) UNIQUE NOT NULL, -- IP address, user ID, or API key
    endpoint VARCHAR(255) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    window_duration INTEGER NOT NULL, -- Duration in seconds
    max_requests INTEGER NOT NULL,
    is_blocked BOOLEAN DEFAULT false,
    blocked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_rate_limits_key ON rate_limits(key);
CREATE INDEX idx_rate_limits_endpoint ON rate_limits(endpoint);
CREATE INDEX idx_rate_limits_window_start ON rate_limits(window_start);
CREATE INDEX idx_rate_limits_is_blocked ON rate_limits(is_blocked);
CREATE INDEX idx_rate_limits_blocked_until ON rate_limits(blocked_until);

-- Constraints
ALTER TABLE rate_limits ADD CONSTRAINT chk_rate_limits_window_duration 
    CHECK (window_duration > 0);
ALTER TABLE rate_limits ADD CONSTRAINT chk_rate_limits_max_requests 
    CHECK (max_requests > 0);
ALTER TABLE rate_limits ADD CONSTRAINT chk_rate_limits_request_count 
    CHECK (request_count >= 0);
```

### 1.7 Audit Log Table

```sql
-- Audit log for compliance and security
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- 'user', 'credential', 'session'
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    session_id VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_ip_address ON audit_logs(ip_address);

-- Constraints
ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_action 
    CHECK (LENGTH(action) >= 1 AND LENGTH(action) <= 100);
ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_resource_type 
    CHECK (resource_type IN ('user', 'credential', 'session', 'challenge', 'rate_limit'));
```

## 2. Database Functions and Triggers

### 2.1 Update Timestamp Trigger

```sql
-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users table
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger for rate_limits table
CREATE TRIGGER update_rate_limits_updated_at 
    BEFORE UPDATE ON rate_limits 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

### 2.2 Credential ID Base64 Trigger

```sql
-- Function to generate Base64URL encoded credential ID
CREATE OR REPLACE FUNCTION generate_credential_id_base64()
RETURNS TRIGGER AS $$
BEGIN
    NEW.credential_id_base64 = encode(NEW.credential_id, 'base64')
        .replace('+', '-')
        .replace('/', '_')
        .replace('=', '');
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for credentials table
CREATE TRIGGER generate_credential_id_base64_trigger
    BEFORE INSERT OR UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION generate_credential_id_base64();
```

### 2.3 Challenge Base64 Trigger

```sql
-- Function to generate Base64URL encoded challenge
CREATE OR REPLACE FUNCTION generate_challenge_base64()
RETURNS TRIGGER AS $$
BEGIN
    NEW.challenge_base64 = encode(NEW.challenge, 'base64')
        .replace('+', '-')
        .replace('/', '_')
        .replace('=', '');
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for challenges table
CREATE TRIGGER generate_challenge_base64_trigger
    BEFORE INSERT OR UPDATE ON challenges
    FOR EACH ROW EXECUTE FUNCTION generate_challenge_base64();
```

### 2.4 Audit Log Trigger

```sql
-- Function to create audit log entries
CREATE OR REPLACE FUNCTION create_audit_log()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (action, resource_type, resource_id, new_values)
        VALUES ('CREATE', TG_TABLE_NAME, NEW.id::text, row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (action, resource_type, resource_id, old_values, new_values)
        VALUES ('UPDATE', TG_TABLE_NAME, NEW.id::text, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (action, resource_type, resource_id, old_values)
        VALUES ('DELETE', TG_TABLE_NAME, OLD.id::text, row_to_json(OLD));
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ language 'plpgsql';

-- Triggers for audit logging
CREATE TRIGGER audit_users_trigger
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION create_audit_log();

CREATE TRIGGER audit_credentials_trigger
    AFTER INSERT OR UPDATE OR DELETE ON credentials
    FOR EACH ROW EXECUTE FUNCTION create_audit_log();

CREATE TRIGGER audit_sessions_trigger
    AFTER INSERT OR UPDATE OR DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION create_audit_log();
```

## 3. Views

### 3.1 User Statistics View

```sql
-- View for user statistics
CREATE VIEW user_statistics AS
SELECT 
    u.id,
    u.username,
    u.created_at,
    u.last_login_at,
    COUNT(c.id) as credential_count,
    COUNT(s.id) as active_sessions,
    MAX(c.last_used_at) as last_credential_use,
    COUNT(DISTINCT aa.id) as total_auth_attempts,
    COUNT(DISTINCT CASE WHEN aa.status = 'success' THEN aa.id END) as successful_auth_attempts,
    COUNT(DISTINCT CASE WHEN aa.status = 'failure' THEN aa.id END) as failed_auth_attempts
FROM users u
LEFT JOIN credentials c ON u.id = c.user_id AND c.is_active = true
LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = true AND s.expires_at > NOW()
LEFT JOIN authentication_attempts aa ON u.username = aa.username
WHERE u.is_active = true
GROUP BY u.id, u.username, u.created_at, u.last_login_at;
```

### 3.2 Security Metrics View

```sql
-- View for security metrics
CREATE VIEW security_metrics AS
SELECT 
    DATE_TRUNC('day', created_at) as date,
    COUNT(*) as total_attempts,
    COUNT(DISTINCT username) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips,
    COUNT(CASE WHEN status = 'success' THEN 1 END) as successful_attempts,
    COUNT(CASE WHEN status = 'failure' THEN 1 END) as failed_attempts,
    COUNT(CASE WHEN status = 'blocked' THEN 1 END) as blocked_attempts,
    COUNT(CASE WHEN attempt_type = 'registration' THEN 1 END) as registration_attempts,
    COUNT(CASE WHEN attempt_type = 'authentication' THEN 1 END) as authentication_attempts
FROM authentication_attempts
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY date DESC;
```

## 4. Database Migration Scripts

### 4.1 Initial Migration (001_initial_schema.sql)

```sql
-- Migration: 001_initial_schema
-- Description: Create initial database schema for FIDO2/WebAuthn server

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create all tables in the correct order
-- (Table definitions from above)

-- Create indexes
-- (Index definitions from above)

-- Create functions and triggers
-- (Function and trigger definitions from above)

-- Create views
-- (View definitions from above)

-- Insert default data
INSERT INTO rate_limits (key, endpoint, window_duration, max_requests) VALUES
('default', '*', 60, 100),
('default', '/api/webauthn/registration/challenge', 60, 10),
('default', '/api/webauthn/authentication/challenge', 60, 20),
('default', '/api/webauthn/registration/verify', 60, 5),
('default', '/api/webauthn/authentication/verify', 60, 10);
```

### 4.2 Add User Verification Column (002_add_user_verification.sql)

```sql
-- Migration: 002_add_user_verification
-- Description: Add user verification settings to users table

ALTER TABLE users ADD COLUMN user_verification VARCHAR(20) DEFAULT 'preferred';
ALTER TABLE users ADD CONSTRAINT chk_users_user_verification 
    CHECK (user_verification IN ('required', 'preferred', 'discouraged'));

-- Update existing users to have preferred verification
UPDATE users SET user_verification = 'preferred' WHERE user_verification IS NULL;
```

### 4.3 Add Device Information (003_add_device_info.sql)

```sql
-- Migration: 003_add_device_info
-- Description: Add device tracking information

ALTER TABLE credentials ADD COLUMN device_name VARCHAR(255);
ALTER TABLE credentials ADD COLUMN device_platform VARCHAR(50);
ALTER TABLE credentials ADD COLUMN first_used_at TIMESTAMP WITH TIME ZONE;

-- Update first_used_at for existing credentials
UPDATE credentials SET first_used_at = created_at WHERE first_used_at IS NULL;

-- Create index
CREATE INDEX idx_credentials_device_platform ON credentials(device_platform);
```

### 4.4 Add Backup Eligibility (004_add_backup_eligibility.sql)

```sql
-- Migration: 004_add_backup_eligibility
-- Description: Add backup eligibility tracking for credentials

ALTER TABLE credentials ADD COLUMN backup_state VARCHAR(20) DEFAULT 'unknown';
ALTER TABLE credentials ADD CONSTRAINT chk_credentials_backup_state 
    CHECK (backup_state IN ('unknown', 'eligible', 'not_eligible', 'backed_up', 'not_backed_up'));

-- Create index
CREATE INDEX idx_credentials_backup_state ON credentials(backup_state);
```

## 5. Performance Optimization

### 5.1 Partitioning for Large Tables

```sql
-- Partition authentication_attempts by date for better performance
CREATE TABLE authentication_attempts_partitioned (
    LIKE authentication_attempts INCLUDING ALL
) PARTITION BY RANGE (created_at);

-- Create monthly partitions
CREATE TABLE authentication_attempts_2024_01 PARTITION OF authentication_attempts_partitioned
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE authentication_attempts_2024_02 PARTITION OF authentication_attempts_partitioned
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

-- Add more partitions as needed
```

### 5.2 Materialized Views for Reporting

```sql
-- Materialized view for daily statistics
CREATE MATERIALIZED VIEW daily_statistics AS
SELECT 
    DATE_TRUNC('day', created_at) as date,
    COUNT(*) as total_auth_attempts,
    COUNT(CASE WHEN status = 'success' THEN 1 END) as successful_auth,
    COUNT(CASE WHEN status = 'failure' THEN 1 END) as failed_auth,
    COUNT(CASE WHEN attempt_type = 'registration' THEN 1 END) as registrations,
    COUNT(CASE WHEN attempt_type = 'authentication' THEN 1 END) as authentications,
    COUNT(DISTINCT username) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips
FROM authentication_attempts
GROUP BY DATE_TRUNC('day', created_at);

-- Create unique index for refresh
CREATE UNIQUE INDEX idx_daily_statistics_date ON daily_statistics(date);

-- Function to refresh materialized view
CREATE OR REPLACE FUNCTION refresh_daily_statistics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY daily_statistics;
END;
$$ LANGUAGE plpgsql;

-- Schedule refresh (requires pg_cron extension)
-- SELECT cron.schedule('refresh-daily-stats', '0 2 * * *', 'SELECT refresh_daily_statistics();');
```

## 6. Security Considerations

### 6.1 Row Level Security

```sql
-- Enable row level security for sensitive tables
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Policy to ensure users can only access their own credentials
CREATE POLICY user_credentials_policy ON credentials
    FOR ALL TO application_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Policy to ensure users can only access their own sessions
CREATE POLICY user_sessions_policy ON sessions
    FOR ALL TO application_user
    USING (user_id = current_setting('app.current_user_id')::uuid);
```

### 6.2 Data Encryption

```sql
-- Extension for data encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Function to encrypt sensitive data
CREATE OR REPLACE FUNCTION encrypt_sensitive_data(data TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(encrypt(data::bytea, 'encryption-key', 'aes'), 'base64');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to decrypt sensitive data
CREATE OR REPLACE FUNCTION decrypt_sensitive_data(encrypted_data TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN convert_from(decrypt(decode(encrypted_data, 'base64'), 'encryption-key', 'aes'), 'UTF8');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

## 7. Monitoring and Maintenance

### 7.1 Health Check Functions

```sql
-- Function to check database health
CREATE OR REPLACE FUNCTION database_health_check()
RETURNS JSONB AS $$
DECLARE
    result JSONB;
    connection_count INTEGER;
    table_sizes JSONB;
BEGIN
    -- Check connection count
    SELECT count(*) INTO connection_count 
    FROM pg_stat_activity 
    WHERE state = 'active';
    
    -- Get table sizes
    SELECT jsonb_build_object(
        'users', pg_total_relation_size('users'),
        'credentials', pg_total_relation_size('credentials'),
        'sessions', pg_total_relation_size('sessions'),
        'authentication_attempts', pg_total_relation_size('authentication_attempts')
    ) INTO table_sizes;
    
    -- Build result
    result := jsonb_build_object(
        'status', 'healthy',
        'timestamp', NOW(),
        'active_connections', connection_count,
        'table_sizes', table_sizes,
        'version', version()
    );
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;
```

### 7.2 Cleanup Functions

```sql
-- Function to cleanup old data
CREATE OR REPLACE FUNCTION cleanup_old_data(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Cleanup old authentication attempts
    DELETE FROM authentication_attempts 
    WHERE created_at < NOW() - INTERVAL '1 day' * retention_days;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Cleanup old audit logs (keep longer)
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - INTERVAL '1 day' * (retention_days * 2);
    
    -- Cleanup expired challenges
    DELETE FROM challenges 
    WHERE expires_at < NOW() - INTERVAL '1 day';
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-old-data', '0 3 * * *', 'SELECT cleanup_old_data();');
```

This comprehensive database schema provides a solid foundation for the FIDO2/WebAuthn server with proper security, performance optimization, and maintenance considerations.