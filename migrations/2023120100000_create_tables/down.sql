-- Drop tables in reverse order due to foreign key constraints
DROP TABLE IF EXISTS authentication_challenges;
DROP TABLE IF EXISTS registration_challenges;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;