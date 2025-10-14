//! Request/Response schema module
//!
//! This module contains all the request and response types for the FIDO2/WebAuthn API
//! endpoints, following the FIDO Alliance Conformance Test API specification.

pub mod attestation;
pub mod assertion;
pub mod common;

pub use attestation::*;
pub use assertion::*;
pub use common::*;