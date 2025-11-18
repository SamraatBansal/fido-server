-- Drop function
DROP FUNCTION IF EXISTS cleanup_expired_challenges();

-- Drop tables in reverse order
DROP TABLE IF EXISTS challenge_states;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;

-- Drop extension
DROP EXTENSION IF EXISTS "uuid-ossp";