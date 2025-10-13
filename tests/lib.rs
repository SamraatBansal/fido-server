//! FIDO2/WebAuthn Test Suite
//! 
//! This module contains comprehensive tests for the FIDO2 WebAuthn server implementation.
//! Tests are organized into modules covering different aspects of the system.

pub mod unit;
pub mod integration;
pub mod security;
pub mod compliance;
pub mod performance;

pub mod common {
    pub mod factories;
    pub mod fixtures;
    pub mod helpers;
    pub mod mocks;
}

use std::collections::HashMap;

/// Test configuration constants
pub mod test_config {
    pub const TEST_RP_ID: &str = "localhost";
    pub const TEST_RP_NAME: &str = "Test RP";
    pub const TEST_RP_ORIGIN: &str = "http://localhost:8080";
    pub const TEST_TIMEOUT: u64 = 60000;
    pub const CHALLENGE_LENGTH_MIN: usize = 16;
    pub const CHALLENGE_LENGTH_MAX: usize = 64;
}

/// Common test utilities
pub struct TestUtils;

impl TestUtils {
    /// Generate a random test username
    pub fn random_username() -> String {
        format!("testuser_{}", uuid::Uuid::new_v4().to_string()[..8].to_string())
    }

    /// Generate a random test display name
    pub fn random_display_name() -> String {
        format!("Test User {}", uuid::Uuid::new_v4().to_string()[..8].to_string())
    }

    /// Create test headers for API requests
    pub fn test_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers
    }
}

/// Test result type for better error handling
pub type TestResult<T> = Result<T, Box<dyn std::error::Error>>;