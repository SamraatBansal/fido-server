//! WebAuthn module
//! 
//! Contains all WebAuthn-related functionality including types, services, and utilities.

pub mod types;
pub mod service;
pub mod database_service;

pub use types::*;
pub use service::*;
// Re-export database service items explicitly to avoid conflicts
pub use database_service::{DatabaseWebAuthnService};