//! FIDO2/WebAuthn Relying Party Server
//! 
//! This library provides a complete FIDO2/WebAuthn Relying Party server implementation
//! that follows the FIDO Alliance conformance test specifications.

pub mod config;
pub mod controllers;
pub mod db;
pub mod dto;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod services;
pub mod utils;

// Re-export commonly used types
pub use error::{WebAuthnError, Result};
pub use dto::common::ServerResponse;

#[cfg(feature = "test-utils")]
pub mod test_utils;