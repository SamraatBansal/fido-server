//! Common test utilities and fixtures for FIDO2/WebAuthn testing

use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

/// Test user data structure
#[derive(Debug, Clone, PartialEq)]
pub struct TestUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

/// Test credential data structure
#[derive(Debug, Clone, PartialEq)]
pub struct TestCredential {
    pub id: String,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub attestation_type: String,
}

/// Test challenge data structure
#[derive(Debug, Clone)]
pub struct TestChallenge {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub challenge_data: String,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

impl TestUser {
    /// Create a new test user
    pub fn new(username: &str, display_name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
        }
    }

    /// Create a valid test user
    pub fn valid() -> Self {
        Self::new("alice", "Alice Smith")
    }

    /// Create an invalid test user (empty username)
    pub fn invalid_empty_username() -> Self {
        Self::new("", "Alice Smith")
    }

    /// Create an invalid test user (username too long)
    pub fn invalid_long_username() -> Self {
        Self::new(&"a".repeat(300), "Alice Smith")
    }

    /// Create an invalid test user (invalid characters)
    pub fn invalid_characters() -> Self {
        Self::new("alice@#$%", "Alice Smith")
    }
}

impl TestCredential {
    /// Create a new test credential
    pub fn new(user_id: Uuid) -> Self {
        Self {
            id: general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
            user_id,
            public_key: vec![1, 2, 3, 4], // Mock public key
            sign_count: 0,
            attestation_type: "packed".to_string(),
        }
    }

    /// Create a valid test credential
    pub fn valid() -> Self {
        Self::new(Uuid::new_v4())
    }
}

impl TestChallenge {
    /// Create a new test challenge
    pub fn new(challenge_type: &str) -> Self {
        let challenge_data = generate_secure_challenge();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: Some(Uuid::new_v4()),
            username: Some("alice".to_string()),
            challenge_data,
            challenge_type: challenge_type.to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        }
    }

    /// Create a registration challenge
    pub fn registration() -> Self {
        Self::new("registration")
    }

    /// Create an authentication challenge
    pub fn authentication() -> Self {
        Self::new("authentication")
    }

    /// Create an expired challenge
    pub fn expired() -> Self {
        let mut challenge = Self::new("registration");
        challenge.expires_at = Utc::now() - chrono::Duration::minutes(1);
        challenge
    }
}

/// Generate a cryptographically secure challenge for testing
pub fn generate_secure_challenge() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a valid attestation options request
pub fn create_attestation_options_request(username: &str, display_name: &str) -> serde_json::Value {
    json!({
        "username": username,
        "displayName": display_name,
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    })
}

/// Generate a valid attestation options request with minimal fields
pub fn create_minimal_attestation_options_request(username: &str) -> serde_json::Value {
    json!({
        "username": username,
        "displayName": "Test User"
    })
}

/// Generate an invalid attestation options request (missing username)
pub fn create_invalid_attestation_options_request_missing_username() -> serde_json::Value {
    json!({
        "displayName": "Alice Smith"
    })
}

/// Generate an invalid attestation options request (empty username)
pub fn create_invalid_attestation_options_request_empty_username() -> serde_json::Value {
    json!({
        "username": "",
        "displayName": "Alice Smith"
    })
}

/// Generate a valid attestation result request
pub fn create_attestation_result_request(challenge: &str) -> serde_json::Value {
    json!({
        "id": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
        "rawId": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
        "response": {
            "attestationObject": general_purpose::URL_SAFE.encode(b"mock_attestation_object"),
            "clientDataJSON": general_purpose::URL_SAFE.encode(
                format!(
                    r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://example.com"}}"#,
                    challenge
                ).as_bytes()
            )
        },
        "type": "public-key"
    })
}

/// Generate an invalid attestation result request (missing id)
pub fn create_invalid_attestation_result_request_missing_id() -> serde_json::Value {
    json!({
        "rawId": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
        "response": {
            "attestationObject": general_purpose::URL_SAFE.encode(b"mock_attestation_object"),
            "clientDataJSON": general_purpose::URL_SAFE.encode(b"mock_client_data")
        },
        "type": "public-key"
    })
}

/// Generate an invalid attestation result request (invalid base64)
pub fn create_invalid_attestation_result_request_invalid_base64() -> serde_json::Value {
    json!({
        "id": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
        "rawId": "invalid_base64!!!",
        "response": {
            "attestationObject": general_purpose::URL_SAFE.encode(b"mock_attestation_object"),
            "clientDataJSON": general_purpose::URL_SAFE.encode(b"mock_client_data")
        },
        "type": "public-key"
    })
}

/// Generate a valid assertion options request
pub fn create_assertion_options_request(username: &str) -> serde_json::Value {
    json!({
        "username": username,
        "userVerification": "preferred"
    })
}

/// Generate a minimal assertion options request
pub fn create_minimal_assertion_options_request(username: &str) -> serde_json::Value {
    json!({
        "username": username
    })
}

/// Generate an invalid assertion options request (missing username)
pub fn create_invalid_assertion_options_request_missing_username() -> serde_json::Value {
    json!({
        "userVerification": "preferred"
    })
}

/// Generate a valid assertion result request
pub fn create_assertion_result_request(challenge: &str, credential_id: &str) -> serde_json::Value {
    json!({
        "id": credential_id,
        "rawId": credential_id,
        "response": {
            "authenticatorData": general_purpose::URL_SAFE.encode(b"mock_authenticator_data"),
            "clientDataJSON": general_purpose::URL_SAFE.encode(
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com"}}"#,
                    challenge
                ).as_bytes()
            ),
            "signature": general_purpose::URL_SAFE.encode(b"mock_signature"),
            "userHandle": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes())
        },
        "type": "public-key"
    })
}

/// Generate an invalid assertion result request (missing signature)
pub fn create_invalid_assertion_result_request_missing_signature() -> serde_json::Value {
    json!({
        "id": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
        "rawId": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
        "response": {
            "authenticatorData": general_purpose::URL_SAFE.encode(b"mock_authenticator_data"),
            "clientDataJSON": general_purpose::URL_SAFE.encode(b"mock_client_data"),
            "userHandle": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes())
        },
        "type": "public-key"
    })
}

/// Generate an assertion result request with replayed challenge
pub fn create_replay_assertion_result_request(old_challenge: &str, credential_id: &str) -> serde_json::Value {
    create_assertion_result_request(old_challenge, credential_id)
}

/// Generate malformed JSON
pub fn create_malformed_json() -> String {
    r#"{"username": "alice", "displayName": "Alice Smith""#.to_string()
}

/// Generate oversized payload
pub fn create_oversized_payload() -> serde_json::Value {
    let large_string = "a".repeat(1000000); // 1MB string
    json!({
        "username": large_string,
        "displayName": "Alice Smith"
    })
}

/// Test data factory for creating various test scenarios
pub struct TestDataFactory;

impl TestDataFactory {
    /// Create a complete registration flow test data set
    pub fn registration_flow() -> (TestUser, serde_json::Value, serde_json::Value) {
        let user = TestUser::valid();
        let options_request = create_attestation_options_request(&user.username, &user.display_name);
        let challenge = generate_secure_challenge();
        let result_request = create_attestation_result_request(&challenge);
        
        (user, options_request, result_request)
    }

    /// Create a complete authentication flow test data set
    pub fn authentication_flow() -> (TestUser, TestCredential, serde_json::Value, serde_json::Value) {
        let user = TestUser::valid();
        let credential = TestCredential::new(user.id);
        let options_request = create_assertion_options_request(&user.username);
        let challenge = generate_secure_challenge();
        let result_request = create_assertion_result_request(&challenge, &credential.id);
        
        (user, credential, options_request, result_request)
    }

    /// Create security test scenarios
    pub fn security_scenarios() -> HashMap<String, serde_json::Value> {
        let mut scenarios = HashMap::new();
        
        // Replay attack
        scenarios.insert("replay_attack".to_string(), 
            create_attestation_result_request("reused_challenge"));
        
        // Invalid signature
        scenarios.insert("invalid_signature".to_string(), 
            json!({
                "id": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
                "rawId": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
                "response": {
                    "attestationObject": general_purpose::URL_SAFE.encode(b"mock_attestation_object"),
                    "clientDataJSON": general_purpose::URL_SAFE.encode(b"mock_client_data")
                },
                "type": "public-key",
                "signature": "invalid_signature"
            }));
        
        // RP ID mismatch
        scenarios.insert("rp_id_mismatch".to_string(), 
            json!({
                "id": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
                "rawId": general_purpose::URL_SAFE.encode(Uuid::new_v4().as_bytes()),
                "response": {
                    "attestationObject": general_purpose::URL_SAFE.encode(b"mock_attestation_object"),
                    "clientDataJSON": general_purpose::URL_SAFE.encode(
                        br#"{"type":"webauthn.create","challenge":"test","origin":"https://malicious.com"}"#
                    )
                },
                "type": "public-key"
            }));
        
        scenarios
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_user_creation() {
        let user = TestUser::valid();
        assert!(!user.username.is_empty());
        assert!(!user.display_name.is_empty());
        assert_ne!(user.id, Uuid::nil());
    }

    #[test]
    fn test_challenge_generation() {
        let challenge1 = generate_secure_challenge();
        let challenge2 = generate_secure_challenge();
        
        assert_ne!(challenge1, challenge2);
        assert!(challenge1.len() >= 16);
        assert!(challenge2.len() >= 16);
    }

    #[test]
    fn test_json_request_creation() {
        let request = create_attestation_options_request("alice", "Alice Smith");
        assert_eq!(request["username"], "alice");
        assert_eq!(request["displayName"], "Alice Smith");
    }

    #[test]
    fn test_security_scenarios() {
        let scenarios = TestDataFactory::security_scenarios();
        assert!(scenarios.contains_key("replay_attack"));
        assert!(scenarios.contains_key("invalid_signature"));
        assert!(scenarios.contains_key("rp_id_mismatch"));
    }
}