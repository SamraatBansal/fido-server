//! Common test setup and utilities for all test modules

use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

// Re-export commonly used items
pub use crate::factories;
pub use crate::utils;
pub use crate::{TEST_RP_ID, TEST_RP_NAME, TEST_ORIGIN};

/// Test application state for integration tests
#[derive(Clone)]
pub struct TestAppState {
    pub temp_dir: Arc<TempDir>,
    pub database_url: Arc<String>,
    pub config: Arc<serde_json::Value>,
}

impl TestAppState {
    /// Create new test application state
    pub async fn new() -> anyhow::Result<Self> {
        let temp_dir = Arc::new(TempDir::new()?);
        let database_url = Arc::new(format!("sqlite:{}", temp_dir.path().join("test.db").display()));
        
        let config = Arc::new(serde_json::json!({
            "server": {
                "host": "127.0.0.1",
                "port": 0, // Let OS choose port
                "tls": {
                    "enabled": false
                }
            },
            "database": {
                "url": *database_url,
                "max_connections": 5
            },
            "webauthn": {
                "rp_id": TEST_RP_ID,
                "rp_name": TEST_RP_NAME,
                "origin": TEST_ORIGIN,
                "timeout": 60000,
                "challenge_expiration": 300
            },
            "security": {
                "rate_limit": {
                    "enabled": true,
                    "requests_per_minute": 100
                },
                "cors": {
                    "allowed_origins": [TEST_ORIGIN]
                }
            },
            "logging": {
                "level": "debug"
            }
        }));
        
        Ok(Self {
            temp_dir,
            database_url,
            config,
        })
    }
}

/// Test context for unit tests
pub struct TestContext {
    pub state: TestAppState,
    pub mock_services: MockServices,
}

/// Mock services for testing
pub struct MockServices {
    pub user_service: Arc<RwLock<Option<Arc<dyn crate::services::UserService>>>>,
    pub credential_service: Arc<RwLock<Option<Arc<dyn crate::services::CredentialService>>>>,
    pub fido_service: Arc<RwLock<Option<Arc<dyn crate::services::FidoService>>>>,
}

impl MockServices {
    pub fn new() -> Self {
        Self {
            user_service: Arc::new(RwLock::new(None)),
            credential_service: Arc::new(RwLock::new(None)),
            fido_service: Arc::new(RwLock::new(None)),
        }
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            state: TestAppState::new().await.unwrap(),
            mock_services: MockServices::new(),
        }
    }
}

/// Setup test environment
pub async fn setup_test() -> TestContext {
    // Initialize logging for tests
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    
    TestContext::default()
}

/// Cleanup test environment
pub async fn cleanup_test(_context: TestContext) {
    // Cleanup is handled by TempDir automatically
}

/// Test HTTP client for integration tests
pub struct TestClient {
    pub client: reqwest::Client,
    pub base_url: String,
}

impl TestClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
            base_url,
        }
    }
    
    pub async fn post(&self, path: &str, json: serde_json::Value) -> reqwest::Response {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&json)
            .send()
            .await
            .unwrap()
    }
    
    pub async fn get(&self, path: &str) -> reqwest::Response {
        let url = format!("{}{}", self.base_url, path);
        self.client.get(&url).send().await.unwrap()
    }
}

/// Common test assertions
pub mod assertions {
    use serde_json::Value;
    
    /// Assert JSON response has required fields for attestation options
    pub fn assert_attestation_options_response(response: &Value) {
        assert!(response.get("challenge").is_some(), "Missing challenge field");
        assert!(response.get("rp").is_some(), "Missing rp field");
        assert!(response.get("user").is_some(), "Missing user field");
        assert!(response.get("pubKeyCredParams").is_some(), "Missing pubKeyCredParams field");
        assert!(response.get("timeout").is_some(), "Missing timeout field");
        assert!(response.get("attestation").is_some(), "Missing attestation field");
        
        // Validate challenge format
        let challenge = response.get("challenge").unwrap().as_str().unwrap();
        crate::assert_valid_base64url!(challenge);
        crate::assert_challenge_length!(challenge);
        
        // Validate RP info
        let rp = response.get("rp").unwrap();
        assert_eq!(rp.get("id").unwrap().as_str().unwrap(), crate::TEST_RP_ID);
        assert_eq!(rp.get("name").unwrap().as_str().unwrap(), crate::TEST_RP_NAME);
        
        // Validate user info
        let user = response.get("user").unwrap();
        assert!(user.get("id").is_some());
        assert!(user.get("name").is_some());
        assert!(user.get("displayName").is_some());
        
        let user_id = user.get("id").unwrap().as_str().unwrap();
        crate::assert_valid_base64url!(user_id);
        crate::assert_user_id_length!(user_id);
    }
    
    /// Assert JSON response has required fields for assertion options
    pub fn assert_assertion_options_response(response: &Value) {
        assert!(response.get("challenge").is_some(), "Missing challenge field");
        assert!(response.get("allowCredentials").is_some(), "Missing allowCredentials field");
        assert!(response.get("userVerification").is_some(), "Missing userVerification field");
        assert!(response.get("timeout").is_some(), "Missing timeout field");
        
        // Validate challenge format
        let challenge = response.get("challenge").unwrap().as_str().unwrap();
        crate::assert_valid_base64url!(challenge);
        crate::assert_challenge_length!(challenge);
        
        // Validate allowCredentials format
        let allow_creds = response.get("allowCredentials").unwrap().as_array().unwrap();
        for cred in allow_creds {
            assert_eq!(cred.get("type").unwrap().as_str().unwrap(), "public-key");
            assert!(cred.get("id").is_some());
            let cred_id = cred.get("id").unwrap().as_str().unwrap();
            crate::assert_valid_base64url!(cred_id);
        }
    }
    
    /// Assert error response format
    pub fn assert_error_response(response: &Value, expected_status: u16, expected_message: &str) {
        assert_eq!(response.get("status").unwrap().as_u64().unwrap(), expected_status as u64);
        let message = response.get("message").unwrap().as_str().unwrap();
        assert!(message.contains(expected_message), "Error message should contain '{}', got '{}'", expected_message, message);
    }
    
    /// Assert success response format
    pub fn assert_success_response(response: &Value) {
        assert_eq!(response.get("status").unwrap().as_str().unwrap(), "ok");
        assert_eq!(response.get("errorMessage").unwrap().as_str().unwrap(), "");
    }
}

/// Test data generators for edge cases
pub mod edge_cases {
    use serde_json::json;
    
    /// Generate request with null values
    pub fn null_values_request() -> serde_json::Value {
        json!({
            "username": null,
            "displayName": null,
            "attestation": null
        })
    }
    
    /// Generate request with empty strings
    pub fn empty_strings_request() -> serde_json::Value {
        json!({
            "username": "",
            "displayName": "",
            "attestation": ""
        })
    }
    
    /// Generate request with special characters
    pub fn special_characters_request() -> serde_json::Value {
        json!({
            "username": "test+special@example.com",
            "displayName": "Test User Ñáéíóú 🚀",
            "attestation": "direct"
        })
    }
    
    /// Generate request with unicode characters
    pub fn unicode_request() -> serde_json::Value {
        json!({
            "username": "用户@例子.公司",
            "displayName": "用户名 🏠",
            "attestation": "direct"
        })
    }
    
    /// Generate malformed JSON
    pub fn malformed_json() -> String {
        "{ \"username\": \"test\", \"displayName\": \"test\"".to_string()
    }
    
    /// Generate extremely large payload
    pub fn large_payload() -> serde_json::Value {
        let large_string = "a".repeat(100_000);
        json!({
            "username": "test@example.com",
            "displayName": large_string,
            "attestation": "direct"
        })
    }
}

/// Security test utilities
pub mod security {
    use crate::factories;
    
    /// Generate replay attack data (reuse old challenge)
    pub fn replay_attack_data() -> (String, serde_json::Value) {
        let old_challenge = factories::generate_challenge();
        let mut request = factories::valid_attestation_result_request();
        
        // Use old challenge in clientDataJSON
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": old_challenge,
            "origin": crate::TEST_ORIGIN,
            "crossOrigin": false
        });
        
        let encoded_client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(client_data.to_string());
        
        request["response"]["clientDataJSON"] = serde_json::Value::String(encoded_client_data);
        
        (old_challenge, request)
    }
    
    /// Generate tampered client data
    pub fn tampered_client_data() -> serde_json::Value {
        let mut request = factories::valid_attestation_result_request();
        
        // Tamper with clientDataJSON
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": factories::generate_challenge(),
            "origin": "https://malicious.com", // Wrong origin
            "crossOrigin": false
        });
        
        let encoded_client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(client_data.to_string());
        
        request["response"]["clientDataJSON"] = serde_json::Value::String(encoded_client_data);
        request
    }
    
    /// Generate request with invalid RP ID
    pub fn invalid_rp_id() -> serde_json::Value {
        let mut request = factories::valid_attestation_result_request();
        
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": factories::generate_challenge(),
            "origin": "https://evil.com",
            "crossOrigin": false
        });
        
        let encoded_client_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(client_data.to_string());
        
        request["response"]["clientDataJSON"] = serde_json::Value::String(encoded_client_data);
        request
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factories;
    
    #[tokio::test]
    async fn test_setup_creates_valid_state() {
        let context = setup_test().await;
        assert!(!context.database_url.is_empty());
        cleanup_test(context).await;
    }
    
    #[test]
    fn test_factories_generate_valid_data() {
        let challenge = factories::generate_challenge();
        crate::assert_valid_base64url!(challenge);
        crate::assert_challenge_length!(&challenge);
        
        let user_id = factories::generate_user_id();
        crate::assert_valid_base64url!(user_id);
        crate::assert_user_id_length!(&user_id);
    }
    
    #[test]
    fn test_edge_cases_generate_valid_requests() {
        let request = edge_cases::special_characters_request();
        assert!(request["username"].is_string());
        assert!(request["displayName"].is_string());
    }
}