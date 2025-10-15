//! FIDO2/WebAuthn API types for conformance testing
//! 
//! This module defines the exact request/response types required by the
//! FIDO Alliance Conformance Test Tools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod attestation;
pub mod assertion;
pub mod common;

pub use attestation::*;
pub use assertion::*;
pub use common::*;

/// Base response type for all FIDO2 API endpoints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    /// Create a successful response
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    /// Create a failed response with error message
    pub fn failed(error_message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: error_message.into(),
        }
    }
}

/// Extension results from client
pub type AuthenticationExtensionsClientOutputs = HashMap<String, serde_json::Value>;

/// Extension inputs for client
pub type AuthenticationExtensionsClientInputs = HashMap<String, serde_json::Value>;