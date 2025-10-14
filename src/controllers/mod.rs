//! Controllers module
//!
//! This module contains all the HTTP request handlers for the FIDO2/WebAuthn API endpoints.

pub mod authentication;
pub mod health;
pub mod registration;

pub use authentication::*;
pub use health::*;
pub use registration::*;