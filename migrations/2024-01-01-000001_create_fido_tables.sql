-- Create FIDO2/WebAuthn database tables
-- Migration: 2024-01-01-000001_create_fido_tables

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for FIDO2/WebAuthn users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Credentials table for WebAuthn credentials
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid UUID,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    transports JSONB,
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE
);

-- Challenges table for preventing replay attacks
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('registration', 'authentication')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authentication sessions table
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked'))
);

-- Audit logs for compliance and security monitoring
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB
);

-- Indexes for performance and security

-- Users table indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Credentials table indexes
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_created_at ON credentials(created_at);
CREATE INDEX idx_credentials_last_used_at ON credentials(last_used_at);

-- Challenges table indexes
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_type ON challenges(challenge_type);

-- Auth sessions table indexes
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_token ON auth_sessions(session_token);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);
CREATE INDEX idx_auth_sessions_status ON auth_sessions(status);

-- Audit logs table indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_ip_address ON audit_logs(ip_address);

-- Constraints for data integrity

-- Ensure credential ID is not empty
ALTER TABLE credentials ADD CONSTRAINT chk_credential_id_not_empty 
    CHECK (length(credential_id) > 0);

-- Ensure public key is not empty
ALTER TABLE credentials ADD CONSTRAINT chk_public_key_not_empty 
    CHECK (length(credential_public_key) > 0);

-- Ensure sign count is non-negative
ALTER TABLE credentials ADD CONSTRAINT chk_sign_count_non_negative 
    CHECK (sign_count >= 0);

-- Ensure challenge is exactly 32 bytes (256 bits)
ALTER TABLE challenges ADD CONSTRAINT chk_challenge_length 
    CHECK (length(challenge) = 32);

-- Ensure challenge expiration is in the future
ALTER TABLE challenges ADD CONSTRAINT chk_expires_future 
    CHECK (expires_at > created_at);

-- Ensure session expiration is in the future
ALTER TABLE auth_sessions ADD CONSTRAINT chk_session_expires_future 
    CHECK (expires_at > created_at);

-- Ensure session token is not empty
ALTER TABLE auth_sessions ADD CONSTRAINT chk_session_token_not_empty 
    CHECK (length(session_token) > 0);

-- Triggers for automatic timestamp updates

-- Update updated_at timestamp for users
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired challenges
CREATE OR REPLACE FUNCTION cleanup_expired_challenges()
RETURNS void AS $$
BEGIN
    DELETE FROM challenges WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    UPDATE auth_sessions 
    SET status = 'expired' 
    WHERE status = 'active' AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create a scheduled job (requires pg_cron extension)
-- This would be set up separately in production
-- SELECT cron.schedule('cleanup-expired-data', '0 */6 * * *', 'SELECT cleanup_expired_challenges(); SELECT cleanup_expired_sessions();');

-- Row Level Security (RLS) for additional security
-- Enable RLS on sensitive tables
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies (example - would be customized based on application needs)
-- Users can only access their own credentials
CREATE POLICY user_credentials_policy ON credentials
    FOR ALL TO application_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Users can only access their own sessions
CREATE POLICY user_sessions_policy ON auth_sessions
    FOR ALL TO application_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Users can only access their own audit logs
CREATE POLICY user_audit_logs_policy ON audit_logs
    FOR ALL TO application_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Comments for documentation
COMMENT ON TABLE users IS 'FIDO2/WebAuthn users';
COMMENT ON TABLE credentials IS 'WebAuthn credentials bound to users';
COMMENT ON TABLE challenges IS 'Challenges for replay attack prevention';
COMMENT ON TABLE auth_sessions IS 'User authentication sessions';
COMMENT ON TABLE audit_logs IS 'Security and compliance audit logs';

COMMENT ON COLUMN users.id IS 'Primary key - UUID v4';
COMMENT ON COLUMN users.username IS 'Unique username (email format recommended)';
COMMENT ON COLUMN users.display_name IS 'Human-readable display name';
COMMENT ON COLUMN users.created_at IS 'Account creation timestamp';
COMMENT ON COLUMN users.updated_at IS 'Last update timestamp';

COMMENT ON COLUMN credentials.id IS 'Primary key - UUID v4';
COMMENT ON COLUMN credentials.user_id IS 'Foreign key to users table';
COMMENT ON COLUMN credentials.credential_id IS 'WebAuthn credential ID (binary)';
COMMENT ON COLUMN credentials.credential_public_key IS 'COSE format public key';
COMMENT ON COLUMN credentials.attestation_type IS 'Attestation format (packed, fido-u2f, etc.)';
COMMENT ON COLUMN credentials.aaguid IS 'Authenticator AAGUID';
COMMENT ON COLUMN credentials.sign_count IS 'Signature counter for replay detection';
COMMENT ON COLUMN credentials.created_at IS 'Credential creation timestamp';
COMMENT ON COLUMN credentials.last_used_at IS 'Last successful authentication';
COMMENT ON COLUMN credentials.transports IS 'Supported transports (JSON array)';
COMMENT ON COLUMN credentials.backup_eligible IS 'Credential eligible for backup';
COMMENT ON COLUMN credentials.backup_state IS 'Current backup state';

COMMENT ON COLUMN challenges.id IS 'Primary key - UUID v4';
COMMENT ON COLUMN challenges.challenge IS 'Cryptographically random challenge (32 bytes)';
COMMENT ON COLUMN challenges.user_id IS 'Associated user (optional)';
COMMENT ON COLUMN challenges.challenge_type IS 'registration or authentication';
COMMENT ON COLUMN challenges.expires_at IS 'Challenge expiration timestamp';
COMMENT ON COLUMN challenges.created_at IS 'Challenge creation timestamp';

COMMENT ON COLUMN auth_sessions.id IS 'Primary key - UUID v4';
COMMENT ON COLUMN auth_sessions.user_id IS 'Foreign key to users table';
COMMENT ON COLUMN auth_sessions.session_token IS 'Secure session token';
COMMENT ON COLUMN auth_sessions.created_at IS 'Session creation timestamp';
COMMENT ON COLUMN auth_sessions.expires_at IS 'Session expiration timestamp';
COMMENT ON COLUMN auth_sessions.last_activity_at IS 'Last activity timestamp';
COMMENT ON COLUMN auth_sessions.status IS 'Session status (active, expired, revoked)';

COMMENT ON COLUMN audit_logs.id IS 'Primary key - UUID v4';
COMMENT ON COLUMN audit_logs.user_id IS 'Associated user (optional for system events)';
COMMENT ON COLUMN audit_logs.event_type IS 'Event type (registration, authentication, failure, etc.)';
COMMENT ON COLUMN audit_logs.description IS 'Human-readable event description';
COMMENT ON COLUMN audit_logs.ip_address IS 'Client IP address';
COMMENT ON COLUMN audit_logs.user_agent IS 'Client user agent string';
COMMENT ON COLUMN audit_logs.created_at IS 'Event timestamp';
COMMENT ON COLUMN audit_logs.metadata IS 'Additional event metadata (JSON)';