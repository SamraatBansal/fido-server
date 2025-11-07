-- Users table for storing user information
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_id BYTEA NOT NULL, -- WebAuthn user.id (base64url decoded)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    active BOOLEAN DEFAULT TRUE NOT NULL
);

-- Credentials table for storing WebAuthn credentials
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL, -- WebAuthn credential ID
    public_key BYTEA NOT NULL,           -- Public key
    counter BIGINT NOT NULL DEFAULT 0,   -- Signature counter (anti-cloning)
    aaguid UUID,                         -- Authenticator AAGUID
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    transports TEXT[],                   -- Available transports
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE,
    attestation_type VARCHAR(50),        -- Attestation type
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_used TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT TRUE NOT NULL
);

-- Challenges table for temporary storage during registration/authentication
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(50) NOT NULL, -- 'registration' or 'authentication'
    session_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed BOOLEAN DEFAULT FALSE NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(active) WHERE active = TRUE;

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(active) WHERE active = TRUE;

CREATE INDEX idx_challenges_challenge ON challenges(challenge);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_session_id ON challenges(session_id);
CREATE INDEX idx_challenges_cleanup ON challenges(expires_at, consumed) WHERE consumed = FALSE;

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();