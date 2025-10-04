-- Create credentials table
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    attestation_format VARCHAR(50),
    aaguid BYTEA,
    transports TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE
);

-- Create indexes
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_created_at ON credentials(created_at);
CREATE INDEX idx_credentials_last_used_at ON credentials(last_used_at);