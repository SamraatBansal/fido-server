//! Data Transfer Object (DTO) module for FIDO2/WebAuthn API compliance

pub mod common;
pub mod registration;
pub mod authentication;

// Re-export commonly used types
pub use common::*;
pub use registration::*;
pub use authentication::*;