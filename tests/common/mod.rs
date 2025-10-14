//! Common test utilities and fixtures for FIDO2/WebAuthn testing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Common test utilities
pub mod fixtures;
pub mod helpers;
pub mod mock_data;

/// Re-export common types
pub use fixtures::*;
pub use helpers::*;
pub use mock_data::*;

/// Base URL for testing
pub const TEST_BASE_URL: &str = "http://localhost:8080";

/// Common headers for API requests
pub fn default_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Accept".to_string(), "application/json".to_string());
    headers
}

/// Test configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            rp_name: "Example Corporation".to_string(),
            rp_id: "example.com".to_string(),
            rp_origin: "https://example.com".to_string(),
            timeout: 60000,
        }
    }
}

/// Server response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == "ok"
    }
}

/// Test result type
pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;