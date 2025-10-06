//! Unit tests for FIDO2/WebAuthn server components

pub mod controllers;
pub mod utils;
pub mod middleware;
pub mod schema_validation;

// Include the webauthn service tests
mod webauthn_service_tests;