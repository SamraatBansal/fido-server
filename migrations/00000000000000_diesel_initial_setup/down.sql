-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_challenges_user_id;
DROP INDEX IF EXISTS idx_challenges_expires_at;
DROP INDEX IF EXISTS idx_challenges_challenge_hash;
DROP INDEX IF EXISTS idx_credentials_credential_id;
DROP INDEX IF EXISTS idx_credentials_user_id;

-- Drop tables
DROP TABLE IF EXISTS challenges;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;

-- Drop custom types
DROP TYPE IF EXISTS user_verification_type;
DROP TYPE IF EXISTS attestation_type;