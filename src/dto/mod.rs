//! Data Transfer Objects for FIDO2/WebAuthn API
//! 
//! This module contains all the request and response DTOs that match
//! the FIDO2 Conformance Test API specification.

pub mod attestation;
pub mod assertion;
pub mod common;

pub use attestation::*;
pub use assertion::*;
pub use common::*;