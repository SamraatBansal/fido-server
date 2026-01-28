-- Drop sessions table and related objects
DROP TRIGGER IF EXISTS update_sessions_last_accessed_at ON sessions;
DROP FUNCTION IF EXISTS update_last_accessed_at_column();
DROP TABLE IF EXISTS sessions;