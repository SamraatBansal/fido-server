//! Common test utilities and fixtures for FIDO2/WebAuthn testing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Common test utilities
pub mod fixtures;
pub mod helpers;
pub mod mock_data;

/// Re-export common types for convenience
pub use fixtures::*;
pub use helpers::*;
pub use mock_data::*;

/// Base URL for testing
pub const TEST_BASE_URL: &str = "http://localhost:8080";

/// Common headers used in tests
pub fn default_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Accept".to_string(), "application/json".to_string());
    headers
}

/// Test configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub base_url: String,
    pub timeout: std::time::Duration,
    pub max_retries: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            base_url: TEST_BASE_URL.to_string(),
            timeout: std::time::Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

/// Standard test response structure
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    pub status: String,
    pub errorMessage: String,
}

impl ServerResponse {
    pub fn is_success(&self) -> bool {
        self.status == "ok"
    }
    
    pub fn is_failure(&self) -> bool {
        self.status == "failed"
    }
}

/// Macro for creating test cases with different scenarios
#[macro_export]
macro_rules! test_cases {
    ($test_name:ident, $test_cases:expr) => {
        $test_cases.iter().for_each(|case| {
            let case_name = format!("{}_{}", stringify!($test_name), case.name);
            #[tokio::test]
            async fn $test_name() {
                case.test_fn().await;
            }
        });
    };
}