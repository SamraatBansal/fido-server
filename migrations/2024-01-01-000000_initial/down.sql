-- Drop all tables in reverse order
DROP TABLE IF EXISTS challenges;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;

-- Drop the trigger function
DROP FUNCTION IF EXISTS update_updated_at_column();