-- Drop function
DROP FUNCTION IF EXISTS cleanup_expired_challenges();

-- Drop indexes
DROP INDEX IF EXISTS idx_challenges_type;
DROP INDEX IF EXISTS idx_challenges_expires_at;
DROP INDEX IF EXISTS idx_challenges_user_id;
DROP INDEX IF EXISTS idx_credentials_credential_id;
DROP INDEX IF EXISTS idx_credentials_user_id;
DROP INDEX IF EXISTS idx_users_username;

-- Drop tables (order matters due to foreign keys)
DROP TABLE IF EXISTS challenges;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;

-- Drop extension
DROP EXTENSION IF EXISTS "uuid-ossp";