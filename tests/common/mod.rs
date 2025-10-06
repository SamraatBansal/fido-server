//! Common test utilities and fixtures for FIDO2/WebAuthn testing

pub mod fixtures;
pub mod mock_server;
pub mod test_helpers;
pub mod test_data;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use base64::{Engine as _, engine::general_purpose};

// Re-export commonly used items
pub use fixtures::*;
pub use mock_server::*;
pub use test_helpers::*;
pub use test_data::*;

/// Test configuration constants
pub mod constants {
    pub const TEST_RP_ID: &str = "localhost";
    pub const TEST_RP_NAME: &str = "Test RP";
    pub const TEST_RP_ORIGIN: &str = "http://localhost:8080";
    pub const TEST_USERNAME: &str = "test@example.com";
    pub const TEST_DISPLAY_NAME: &str = "Test User";
    pub const CHALLENGE_TIMEOUT_SECONDS: u64 = 300;
    pub const RATE_LIMIT_REQUESTS: u32 = 100;
}

/// Common error types for testing
#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 encoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    
    #[error("UUID parsing error: {0}")]
    Uuid(#[from] uuid::Error),
    
    #[error("Test setup error: {0}")]
    Setup(String),
    
    #[error("Mock server error: {0}")]
    MockServer(String),
}

/// Test result type
pub type TestResult<T> = Result<T, TestError>;

/// Trait for test data generation
pub trait TestDataFactory {
    fn create_valid() -> Self;
    fn create_invalid() -> Self;
    fn create_edge_case() -> Self;
}

/// Common test context
#[derive(Debug, Clone)]
pub struct TestContext {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub credential_id: String,
    pub challenge: String,
    pub created_at: DateTime<Utc>,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            user_id: Uuid::new_v4(),
            username: constants::TEST_USERNAME.to_string(),
            display_name: constants::TEST_DISPLAY_NAME.to_string(),
            credential_id: general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
            challenge: general_purpose::URL_SAFE.encode(rand::random::<[u8; 32]>()),
            created_at: Utc::now(),
        }
    }
}