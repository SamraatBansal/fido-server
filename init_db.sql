-- Initialize database for FIDO2 server
-- This script runs when the PostgreSQL container starts

-- Create the database if it doesn't exist (this is handled by the environment variables)
-- POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE fido_db TO fido_user;

-- Create the uuid extension if it doesn't exist (will be created by migrations)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";