-- FIDO2/WebAuthn Database Schema
-- PostgreSQL schema for users, credentials, and challenges

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attestation_format TEXT NOT NULL,
    aaguid BYTEA
);

-- Challenges table
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_challenges_challenge ON challenges(challenge);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);