//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod schema;
pub mod services;
pub mod utils;

pub use error::{AppError, Result};

// Re-export common types for convenience
pub use crate::config::{AppConfig, DatabaseConfig, WebAuthnConfig};
pub use crate::services::{
    FidoService, UserService, CredentialService, 
    SecureSessionManager, AttestationVerifier, JwtManager, AuditLogger
};
pub use crate::db::repositories::{UserRepository, CredentialRepository, SessionRepository};
pub use crate::db::connection::DbPool;