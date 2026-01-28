-- Drop credentials table and related objects
DROP TRIGGER IF EXISTS update_credentials_updated_at ON credentials;
DROP TABLE IF EXISTS credentials;