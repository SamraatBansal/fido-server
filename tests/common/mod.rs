//! Common test utilities and fixtures for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Common test utilities and fixtures
pub mod fixtures;
pub mod mocks;
pub mod testcontainers;
pub mod webauthn_fixtures;

/// Re-export common test utilities
pub use fixtures::*;
pub use mocks::*;
pub use webauthn_fixtures::*;

/// Test configuration constants
pub const TEST_RP_ID: &str = "localhost";
pub const TEST_RP_ORIGIN: &str = "https://localhost:8443";
pub const TEST_RP_NAME: &str = "FIDO2 Test Server";
pub const TEST_TIMEOUT: u64 = 60000;

/// Default test user
pub fn default_test_user() -> TestUser {
    TestUser {
        id: BASE64.encode(Uuid::new_v4().as_bytes()),
        name: "testuser@example.com".to_string(),
        display_name: "Test User".to_string(),
    }
}

/// Test user struct for generating test data
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

impl TestUser {
    pub fn new(name: &str, display_name: &str) -> Self {
        Self {
            id: BASE64.encode(Uuid::new_v4().as_bytes()),
            name: name.to_string(),
            display_name: display_name.to_string(),
        }
    }

    pub fn with_id(id: &str, name: &str, display_name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            display_name: display_name.to_string(),
        }
    }
}

/// Test credential struct
#[derive(Debug, Clone)]
pub struct TestCredential {
    pub id: String,
    pub raw_id: String,
    pub r#type: String,
    pub response: CredentialResponse,
}

#[derive(Debug, Clone)]
pub struct CredentialResponse {
    pub attestation_object: Option<String>,
    pub client_data_json: String,
    pub authenticator_data: Option<String>,
    pub signature: Option<String>,
    pub user_handle: Option<String>,
}

impl TestCredential {
    pub fn new_registration(
        id: &str,
        attestation_object: &str,
        client_data_json: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            raw_id: id.to_string(),
            r#type: "public-key".to_string(),
            response: CredentialResponse {
                attestation_object: Some(attestation_object.to_string()),
                client_data_json: client_data_json.to_string(),
                authenticator_data: None,
                signature: None,
                user_handle: None,
            },
        }
    }

    pub fn new_authentication(
        id: &str,
        authenticator_data: &str,
        client_data_json: &str,
        signature: &str,
        user_handle: Option<&str>,
    ) -> Self {
        Self {
            id: id.to_string(),
            raw_id: id.to_string(),
            r#type: "public-key".to_string(),
            response: CredentialResponse {
                attestation_object: None,
                client_data_json: client_data_json.to_string(),
                authenticator_data: Some(authenticator_data.to_string()),
                signature: Some(signature.to_string()),
                user_handle: user_handle.map(|uh| uh.to_string()),
            },
        }
    }
}

/// Test challenge generator
pub fn generate_test_challenge() -> String {
    BASE64.encode(rand::random::<[u8; 32]>())
}

/// Test timestamp generator
pub fn test_timestamp() -> DateTime<Utc> {
    Utc::now()
}

/// Helper to create JSON values for testing
pub fn json_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("Failed to serialize test value")
}

/// Helper to create base64url encoded test data
pub fn base64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Helper to decode base64url test data
pub fn base64url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

/// Test error helper
#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    
    #[error("Invalid test data: {0}")]
    InvalidData(String),
}

/// Result type for test operations
pub type TestResult<T> = Result<T, TestError>;

/// Test assertion helpers
pub mod assertions {
    use super::*;
    
    /// Assert that a JSON response contains required fields
    pub fn assert_has_fields(response: &Value, fields: &[&str]) {
        for field in fields {
            assert!(
                response.get(field).is_some(),
                "Missing required field: {}",
                field
            );
        }
    }
    
    /// Assert that a base64 string is valid
    pub fn assert_valid_base64(s: &str) {
        BASE64.decode(s).expect("Invalid base64 string");
    }
    
    /// Assert that a base64url string is valid
    pub fn assert_valid_base64url(s: &str) {
        base64url_decode(s).expect("Invalid base64url string");
    }
    
    /// Assert that a challenge is properly formatted
    pub fn assert_valid_challenge(challenge: &str) {
        assert!(!challenge.is_empty(), "Challenge cannot be empty");
        assert_valid_base64url(challenge);
        assert!(challenge.len() >= 16, "Challenge too short");
    }
}

/// Test data generators for property-based testing
pub mod generators {
    use proptest::prelude::*;
    
    /// Generate valid email addresses
    pub fn arb_email() -> impl Strategy<Value = String> {
        prop::string::string_regex(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            .unwrap()
            .prop_filter("Valid email", |s| s.len() <= 255)
    }
    
    /// Generate valid display names
    pub fn arb_display_name() -> impl Strategy<Value = String> {
        prop::string::string_regex(r"[a-zA-Z0-9 ]{1,100}")
            .unwrap()
    }
    
    /// Generate valid base64url strings
    pub fn arb_base64url() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<u8>(), 16..64)
            .prop_map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
    
    /// Generate valid challenges
    pub fn arb_challenge() -> impl Strategy<Value = String> {
        arb_base64url().prop_filter("Valid challenge", |s| s.len() >= 16)
    }
}

/// Test environment configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
    pub timeout: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            rp_id: TEST_RP_ID.to_string(),
            rp_origin: TEST_RP_ORIGIN.to_string(),
            rp_name: TEST_RP_NAME.to_string(),
            timeout: TEST_TIMEOUT,
        }
    }
}

/// Test context for managing test state
#[derive(Debug)]
pub struct TestContext {
    pub config: TestConfig,
    pub users: HashMap<String, TestUser>,
    pub credentials: HashMap<String, TestCredential>,
    pub challenges: HashMap<String, DateTime<Utc>>,
}

impl TestContext {
    pub fn new() -> Self {
        Self {
            config: TestConfig::default(),
            users: HashMap::new(),
            credentials: HashMap::new(),
            challenges: HashMap::new(),
        }
    }
    
    pub fn with_config(config: TestConfig) -> Self {
        Self {
            config,
            users: HashMap::new(),
            credentials: HashMap::new(),
            challenges: HashMap::new(),
        }
    }
    
    pub fn add_user(&mut self, user: TestUser) {
        self.users.insert(user.name.clone(), user);
    }
    
    pub fn add_credential(&mut self, id: String, credential: TestCredential) {
        self.credentials.insert(id, credential);
    }
    
    pub fn add_challenge(&mut self, challenge: String) {
        self.challenges.insert(challenge, Utc::now());
    }
    
    pub fn get_user(&self, username: &str) -> Option<&TestUser> {
        self.users.get(username)
    }
    
    pub fn get_credential(&self, id: &str) -> Option<&TestCredential> {
        self.credentials.get(id)
    }
    
    pub fn challenge_exists(&self, challenge: &str) -> bool {
        self.challenges.contains_key(challenge)
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}