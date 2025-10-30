//! Database module

pub mod connection;
pub mod models;
pub mod repositories;
pub mod repositories_impl;

pub use connection::{PgPool, create_pool, get_database_url, run_migrations};
pub use models::{User, NewUser, UpdateUser, Credential, NewCredential, UpdateCredential, Challenge, NewChallenge};
pub use repositories::{UserRepository, CredentialRepository, ChallengeRepository};
pub use repositories_impl::{PgUserRepository, PgCredentialRepository, PgChallengeRepository};