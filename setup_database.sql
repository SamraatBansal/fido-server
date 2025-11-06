-- Setup script for FIDO2 WebAuthn server database
-- Run this as PostgreSQL superuser

-- Create database and user
CREATE DATABASE fido_db;
CREATE USER fido_user WITH ENCRYPTED PASSWORD 'fido_password';
GRANT ALL PRIVILEGES ON DATABASE fido_db TO fido_user;

-- Connect to the database and set up permissions
\c fido_db;
GRANT ALL ON SCHEMA public TO fido_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fido_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fido_user;

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";