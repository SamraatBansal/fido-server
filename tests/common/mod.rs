//! Common test utilities and fixtures for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

/// Test data factory for generating valid/invalid WebAuthn payloads
pub struct TestDataFactory;

impl TestDataFactory {
    /// Generate a valid base64url-encoded challenge
    pub fn valid_challenge() -> String {
        let challenge = rand::random::<[u8; 32]>();
        URL_SAFE_NO_PAD.encode(challenge)
    }

    /// Generate an invalid challenge (too short)
    pub fn invalid_challenge_short() -> String {
        URL_SAFE_NO_PAD.encode([1u8; 8])
    }

    /// Generate a valid user ID
    pub fn valid_user_id() -> String {
        URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
    }

    /// Generate an invalid user ID (too long)
    pub fn invalid_user_id_long() -> String {
        URL_SAFE_NO_PAD.encode([1u8; 65]) // Exceeds 64 byte limit
    }

    /// Generate a valid credential ID
    pub fn valid_credential_id() -> String {
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
    }

    /// Generate an invalid credential ID (empty)
    pub fn invalid_credential_id_empty() -> String {
        String::new()
    }

    /// Generate a valid attestation options request
    pub fn valid_attestation_options_request() -> serde_json::Value {
        json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith",
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Generate an attestation options request with missing username
    pub fn attestation_options_missing_username() -> serde_json::Value {
        json!({
            "displayName": "Alice Smith",
            "attestation": "direct"
        })
    }

    /// Generate an attestation options request with invalid attestation type
    pub fn attestation_options_invalid_attestation() -> serde_json::Value {
        json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith",
            "attestation": "invalid_type"
        })
    }

    /// Generate a valid attestation result request
    pub fn valid_attestation_result_request() -> serde_json::Value {
        json!({
            "id": Self::valid_credential_id(),
            "rawId": Self::valid_credential_id(),
            "response": {
                "attestationObject": Self::valid_attestation_object(),
                "clientDataJSON": Self::valid_client_data_json()
            },
            "type": "public-key"
        })
    }

    /// Generate an attestation result request with missing response
    pub fn attestation_result_missing_response() -> serde_json::Value {
        json!({
            "id": Self::valid_credential_id(),
            "rawId": Self::valid_credential_id(),
            "type": "public-key"
        })
    }

    /// Generate an attestation result request with invalid type
    pub fn attestation_result_invalid_type() -> serde_json::Value {
        json!({
            "id": Self::valid_credential_id(),
            "rawId": Self::valid_credential_id(),
            "response": {
                "attestationObject": Self::valid_attestation_object(),
                "clientDataJSON": Self::valid_client_data_json()
            },
            "type": "invalid-type"
        })
    }

    /// Generate a valid assertion options request
    pub fn valid_assertion_options_request() -> serde_json::Value {
        json!({
            "username": "alice@example.com",
            "userVerification": "preferred"
        })
    }

    /// Generate an assertion options request with missing username
    pub fn assertion_options_missing_username() -> serde_json::Value {
        json!({
            "userVerification": "preferred"
        })
    }

    /// Generate a valid assertion result request
    pub fn valid_assertion_result_request() -> serde_json::Value {
        json!({
            "id": Self::valid_credential_id(),
            "rawId": Self::valid_credential_id(),
            "response": {
                "authenticatorData": Self::valid_authenticator_data(),
                "clientDataJSON": Self::valid_client_data_json(),
                "signature": Self::valid_signature(),
                "userHandle": Self::valid_user_id()
            },
            "type": "public-key"
        })
    }

    /// Generate an assertion result request with missing signature
    pub fn assertion_result_missing_signature() -> serde_json::Value {
        json!({
            "id": Self::valid_credential_id(),
            "rawId": Self::valid_credential_id(),
            "response": {
                "authenticatorData": Self::valid_authenticator_data(),
                "clientDataJSON": Self::valid_client_data_json(),
                "userHandle": Self::valid_user_id()
            },
            "type": "public-key"
        })
    }

    /// Generate a valid attestation object (mock)
    pub fn valid_attestation_object() -> String {
        // Mock CBOR-encoded attestation object
        URL_SAFE_NO_PAD.encode([1u8; 100])
    }

    /// Generate an invalid attestation object (malformed base64url)
    pub fn invalid_attestation_object() -> String {
        "invalid_base64url!".to_string()
    }

    /// Generate valid client data JSON
    pub fn valid_client_data_json() -> String {
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": Self::valid_challenge(),
            "origin": "https://example.com",
            "crossOrigin": false
        });
        URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes())
    }

    /// Generate client data JSON with invalid origin
    pub fn client_data_invalid_origin() -> String {
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": Self::valid_challenge(),
            "origin": "https://malicious.com",
            "crossOrigin": false
        });
        URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes())
    }

    /// Generate client data JSON with expired challenge
    pub fn client_data_expired_challenge() -> String {
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": "expired_challenge_12345",
            "origin": "https://example.com",
            "crossOrigin": false
        });
        URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes())
    }

    /// Generate valid authenticator data
    pub fn valid_authenticator_data() -> String {
        // Mock authenticator data (37 bytes minimum)
        URL_SAFE_NO_PAD.encode([1u8; 37])
    }

    /// Generate invalid authenticator data (too short)
    pub fn invalid_authenticator_data() -> String {
        URL_SAFE_NO_PAD.encode([1u8; 10]) // Less than 37 bytes
    }

    /// Generate a valid signature
    pub fn valid_signature() -> String {
        // Mock ECDSA signature
        URL_SAFE_NO_PAD.encode([1u8; 64])
    }

    /// Generate an invalid signature (malformed base64url)
    pub fn invalid_signature() -> String {
        "invalid_signature!".to_string()
    }

    /// Generate oversized payload
    pub fn oversized_payload() -> serde_json::Value {
        let large_string = "x".repeat(1_000_000); // 1MB string
        json!({
            "username": "alice@example.com",
            "displayName": large_string,
            "attestation": "direct"
        })
    }

    /// Generate payload with null values
    pub fn payload_with_nulls() -> serde_json::Value {
        json!({
            "username": null,
            "displayName": "Alice Smith",
            "attestation": "direct"
        })
    }

    /// Generate valid attestation options response
    pub fn valid_attestation_options_response() -> serde_json::Value {
        json!({
            "challenge": Self::valid_challenge(),
            "rp": {
                "name": "Example RP",
                "id": "example.com"
            },
            "user": {
                "id": Self::valid_user_id(),
                "name": "alice@example.com",
                "displayName": "Alice Smith"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7}
            ],
            "timeout": 60000,
            "attestation": "direct"
        })
    }

    /// Generate valid assertion options response
    pub fn valid_assertion_options_response() -> serde_json::Value {
        json!({
            "challenge": Self::valid_challenge(),
            "rpId": "example.com",
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": Self::valid_credential_id()
                }
            ],
            "timeout": 60000,
            "userVerification": "preferred"
        })
    }

    /// Generate valid success response
    pub fn valid_success_response() -> serde_json::Value {
        json!({
            "status": "ok",
            "errorMessage": ""
        })
    }

    /// Generate error response
    pub fn error_response(message: &str) -> serde_json::Value {
        json!({
            "status": "error",
            "errorMessage": message
        })
    }
}

/// Security test vectors for attack scenarios
pub struct SecurityVectors;

impl SecurityVectors {
    /// Generate replay attack payload (reused challenge)
    pub fn replay_attack_payload() -> serde_json::Value {
        json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "attestationObject": TestDataFactory::valid_attestation_object(),
                "clientDataJSON": TestDataFactory::client_data_expired_challenge()
            },
            "type": "public-key"
        })
    }

    /// Generate payload with tampered client data
    pub fn tampered_client_data() -> serde_json::Value {
        json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "attestationObject": TestDataFactory::valid_attestation_object(),
                "clientDataJSON": TestDataFactory::client_data_invalid_origin()
            },
            "type": "public-key"
        })
    }

    /// Generate payload with invalid RP ID
    pub fn invalid_rp_id_payload() -> serde_json::Value {
        json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith",
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            },
            "rpId": "malicious.com" // Invalid RP ID
        })
    }

    /// Generate credential hijacking attempt
    pub fn credential_hijacking_attempt() -> serde_json::Value {
        json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "authenticatorData": TestDataFactory::valid_authenticator_data(),
                "clientDataJSON": TestDataFactory::valid_client_data_json(),
                "signature": TestDataFactory::invalid_signature(),
                "userHandle": TestDataFactory::valid_user_id()
            },
            "type": "public-key"
        })
    }

    /// Generate malformed CBOR data
    pub fn malformed_cbor() -> String {
        "invalid_cbor_data".to_string()
    }

    /// Generate broken base64url string
    pub fn broken_base64url() -> String {
        "invalid_base64url_with_!@#$%^&*()".to_string()
    }

    /// Generate truncated client data JSON
    pub fn truncated_client_data() -> String {
        URL_SAFE_NO_PAD.encode(b"{\"type\": \"webauthn.create\"")
    }
}

/// Performance test data generators
pub struct PerformanceData;

impl PerformanceData {
    /// Generate bulk registration requests
    pub fn bulk_registration_requests(count: usize) -> Vec<serde_json::Value> {
        (0..count)
            .map(|i| {
                json!({
                    "username": format!("user{}@example.com", i),
                    "displayName": format!("User {}", i),
                    "attestation": "direct",
                    "authenticatorSelection": {
                        "authenticatorAttachment": "platform",
                        "requireResidentKey": false,
                        "userVerification": "preferred"
                    }
                })
            })
            .collect()
    }

    /// Generate bulk authentication requests
    pub fn bulk_authentication_requests(count: usize) -> Vec<serde_json::Value> {
        (0..count)
            .map(|_| {
                json!({
                    "username": "alice@example.com",
                    "userVerification": "preferred"
                })
            })
            .collect()
    }
}

/// Test configuration builder
pub struct TestConfig {
    config: HashMap<String, String>,
}

impl TestConfig {
    pub fn new() -> Self {
        let mut config = HashMap::new();
        config.insert("rp_id".to_string(), "example.com".to_string());
        config.insert("rp_name".to_string(), "Example RP".to_string());
        config.insert("origin".to_string(), "https://example.com".to_string());
        config.insert("challenge_timeout".to_string(), "300".to_string());
        config.insert("max_credentials_per_user".to_string(), "10".to_string());
        
        Self { config }
    }

    pub fn with_rp_id(mut self, rp_id: &str) -> Self {
        self.config.insert("rp_id".to_string(), rp_id.to_string());
        self
    }

    pub fn with_origin(mut self, origin: &str) -> Self {
        self.config.insert("origin".to_string(), origin.to_string());
        self
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.config.get(key)
    }

    pub fn build(self) -> HashMap<String, String> {
        self.config
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_challenge_generation() {
        let challenge = TestDataFactory::valid_challenge();
        assert!(!challenge.is_empty());
        assert!(challenge.len() >= 32); // Base64url encoded 32 bytes
    }

    #[test]
    fn test_invalid_challenge_short() {
        let challenge = TestDataFactory::invalid_challenge_short();
        assert!(!challenge.is_empty());
        assert!(challenge.len() < 32); // Should be shorter than valid
    }

    #[test]
    fn test_valid_user_id_generation() {
        let user_id = TestDataFactory::valid_user_id();
        assert!(!user_id.is_empty());
        assert!(user_id.len() <= 64); // Should be within limits
    }

    #[test]
    fn test_invalid_user_id_long() {
        let user_id = TestDataFactory::invalid_user_id_long();
        assert!(!user_id.is_empty());
        assert!(user_id.len() > 64); // Should exceed limits
    }

    #[test]
    fn test_valid_attestation_options_request() {
        let request = TestDataFactory::valid_attestation_options_request();
        assert!(request.get("username").is_some());
        assert!(request.get("displayName").is_some());
        assert!(request.get("attestation").is_some());
    }

    #[test]
    fn test_attestation_options_missing_username() {
        let request = TestDataFactory::attestation_options_missing_username();
        assert!(request.get("username").is_none());
        assert!(request.get("displayName").is_some());
    }

    #[test]
    fn test_security_vectors() {
        let replay_payload = SecurityVectors::replay_attack_payload();
        assert!(replay_payload.get("id").is_some());
        assert!(replay_payload.get("response").is_some());

        let tampered_payload = SecurityVectors::tampered_client_data();
        assert!(tampered_payload.get("id").is_some());
        assert!(tampered_payload.get("response").is_some());
    }

    #[test]
    fn test_performance_data_generation() {
        let requests = PerformanceData::bulk_registration_requests(5);
        assert_eq!(requests.len(), 5);
        
        for (i, request) in requests.iter().enumerate() {
            let username = request.get("username").unwrap().as_str().unwrap();
            assert_eq!(username, format!("user{}@example.com", i));
        }
    }

    #[test]
    fn test_test_config() {
        let config = TestConfig::new()
            .with_rp_id("test.com")
            .with_origin("https://test.com")
            .build();

        assert_eq!(config.get("rp_id"), Some(&"test.com".to_string()));
        assert_eq!(config.get("origin"), Some(&"https://test.com".to_string()));
    }
}