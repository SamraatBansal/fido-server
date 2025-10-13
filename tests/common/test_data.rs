//! Test data generators and factories

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Test data factory for generating various test scenarios
pub struct TestDataFactory;

impl TestDataFactory {
    /// Generate valid attestation options request with custom parameters
    pub fn attestation_options_request(
        username: Option<&str>,
        display_name: Option<&str>,
        attestation: Option<&str>,
    ) -> Value {
        json!({
            "username": username.unwrap_or("alice"),
            "displayName": display_name.unwrap_or("Alice Smith"),
            "attestation": attestation.unwrap_or("direct"),
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Generate valid attestation result request
    pub fn attestation_result_request(
        credential_id: Option<&str>,
        challenge: Option<&str>,
        origin: Option<&str>,
    ) -> Value {
        let cred_id = credential_id.unwrap_or(&Self::random_credential_id());
        let challenge = challenge.unwrap_or(&Self::random_challenge());
        let origin = origin.unwrap_or("https://example.com");
        
        json!({
            "id": cred_id,
            "rawId": cred_id,
            "response": {
                "attestationObject": Self::mock_attestation_object(),
                "clientDataJSON": Self::client_data_json(challenge, origin, "webauthn.create")
            },
            "type": "public-key"
        })
    }

    /// Generate valid assertion options request
    pub fn assertion_options_request(
        username: Option<&str>,
        user_verification: Option<&str>,
    ) -> Value {
        json!({
            "username": username.unwrap_or("alice"),
            "userVerification": user_verification.unwrap_or("preferred")
        })
    }

    /// Generate valid assertion result request
    pub fn assertion_result_request(
        credential_id: Option<&str>,
        challenge: Option<&str>,
        origin: Option<&str>,
        user_handle: Option<&str>,
    ) -> Value {
        let cred_id = credential_id.unwrap_or(&Self::random_credential_id());
        let challenge = challenge.unwrap_or(&Self::random_challenge());
        let origin = origin.unwrap_or("https://example.com");
        let user_handle = user_handle.unwrap_or(&Self::random_user_handle());
        
        json!({
            "id": cred_id,
            "rawId": cred_id,
            "response": {
                "authenticatorData": Self::mock_authenticator_data(),
                "clientDataJSON": Self::client_data_json(challenge, origin, "webauthn.get"),
                "signature": Self::mock_signature(),
                "userHandle": user_handle
            },
            "type": "public-key"
        })
    }

    /// Generate random challenge
    pub fn random_challenge() -> String {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate random credential ID
    pub fn random_credential_id() -> String {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate random user handle
    pub fn random_user_handle() -> String {
        let mut bytes = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate mock attestation object
    pub fn mock_attestation_object() -> String {
        let mock_data = json!({
            "fmt": "packed",
            "attStmt": {
                "alg": -7,
                "sig": URL_SAFE_NO_PAD.encode("mock_signature_data"),
                "x5c": [URL_SAFE_NO_PAD.encode("mock_certificate_data")]
            },
            "authData": Self::mock_authenticator_data()
        });
        
        URL_SAFE_NO_PAD.encode(mock_data.to_string())
    }

    /// Generate mock authenticator data
    pub fn mock_authenticator_data() -> String {
        // 37 bytes of authenticator data (mock)
        let mut data = vec![0u8; 37];
        // RP ID hash (32 bytes)
        data[0..32].copy_from_slice(&[0x01; 32]);
        // Flags (1 byte)
        data[32] = 0x41; // User present + User verified
        // Counter (4 bytes)
        data[33..37].copy_from_slice(&1u32.to_be_bytes());
        
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Generate mock signature
    pub fn mock_signature() -> String {
        let mut signature = vec![0u8; 64]; // ECDSA signature
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut signature);
        URL_SAFE_NO_PAD.encode(signature)
    }

    /// Generate client data JSON
    pub fn client_data_json(challenge: &str, origin: &str, operation_type: &str) -> String {
        let client_data = json!({
            "type": operation_type,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        });
        
        URL_SAFE_NO_PAD.encode(client_data.to_string())
    }

    /// Generate batch of test users
    pub fn generate_test_users(count: usize) -> Vec<Value> {
        (0..count)
            .map(|i| {
                json!({
                    "username": format!("testuser{}", i),
                    "displayName": format!("Test User {}", i),
                    "id": URL_SAFE_NO_PAD.encode(format!("user_handle_{}", i))
                })
            })
            .collect()
    }

    /// Generate batch of credentials for a user
    pub fn generate_user_credentials(user_id: &str, count: usize) -> Vec<Value> {
        (0..count)
            .map(|i| {
                json!({
                    "id": Self::random_credential_id(),
                    "type": "public-key",
                    "user_id": user_id,
                    "created_at": Utc::now().to_rfc3339(),
                    "last_used_at": Utc::now().to_rfc3339(),
                    "sign_count": i as i64
                })
            })
            .collect()
    }

    /// Generate security test vectors
    pub fn security_test_vectors() -> HashMap<&'static str, Value> {
        let mut vectors = HashMap::new();
        
        // Replay attack vector
        vectors.insert("replay_attack", json!({
            "description": "Replay attack with old challenge",
            "request": Self::attestation_result_request(
                None,
                Some("old_reused_challenge"),
                None
            )
        }));
        
        // Origin mismatch vector
        vectors.insert("origin_mismatch", json!({
            "description": "Request with mismatched origin",
            "request": Self::attestation_result_request(
                None,
                None,
                Some("https://malicious.com")
            )
        }));
        
        // Invalid signature vector
        vectors.insert("invalid_signature", json!({
            "description": "Request with invalid signature",
            "request": {
                "id": Self::random_credential_id(),
                "rawId": Self::random_credential_id(),
                "response": {
                    "attestationObject": Self::mock_attestation_object(),
                    "clientDataJSON": Self::client_data_json(
                        &Self::random_challenge(),
                        "https://example.com",
                        "webauthn.create"
                    ),
                    "signature": URL_SAFE_NO_PAD.encode("invalid_signature_data")
                },
                "type": "public-key"
            }
        }));
        
        // Truncated data vector
        vectors.insert("truncated_data", json!({
            "description": "Request with truncated client data",
            "request": {
                "id": Self::random_credential_id(),
                "rawId": Self::random_credential_id(),
                "response": {
                    "attestationObject": Self::mock_attestation_object(),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode("truncated")
                },
                "type": "public-key"
            }
        }));
        
        vectors
    }

    /// Generate performance test data
    pub fn performance_test_data() -> HashMap<&'static str, Vec<Value>> {
        let mut data = HashMap::new();
        
        // Concurrent registration requests
        data.insert("concurrent_registration", 
            (0..100).map(|i| 
                Self::attestation_options_request(
                    Some(&format!("user{}", i)),
                    Some(&format!("User {}", i)),
                    None
                )
            ).collect()
        );
        
        // Concurrent authentication requests
        data.insert("concurrent_authentication",
            (0..100).map(|_| 
                Self::assertion_options_request(None, None)
            ).collect()
        );
        
        // Large batch requests
        data.insert("large_batch",
            (0..1000).map(|i|
                Self::attestation_options_request(
                    Some(&format!("batch_user_{}", i)),
                    Some(&format!("Batch User {}", i)),
                    None
                )
            ).collect()
        );
        
        data
    }

    /// Generate compliance test data for FIDO2 specification
    pub fn compliance_test_data() -> HashMap<&'static str, Value> {
        let mut data = HashMap::new();
        
        // All supported algorithms
        data.insert("all_algorithms", json!({
            "description": "Request with all supported algorithms",
            "request": {
                "username": "alice",
                "displayName": "Alice Smith",
                "attestation": "direct",
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": -7 },   // ES256
                    { "type": "public-key", "alg": -257 }, // RS256
                    { "type": "public-key", "alg": -37 },  // ES384
                    { "type": "public-key", "alg": -8 }    // Ed25519
                ]
            }
        }));
        
        // Resident key requirement
        data.insert("resident_key", json!({
            "description": "Request with resident key requirement",
            "request": {
                "username": "alice",
                "displayName": "Alice Smith",
                "attestation": "direct",
                "authenticatorSelection": {
                    "requireResidentKey": true,
                    "userVerification": "required"
                }
            }
        }));
        
        // User verification required
        data.insert("user_verification_required", json!({
            "description": "Request with required user verification",
            "request": {
                "username": "alice",
                "displayName": "Alice Smith",
                "authenticatorSelection": {
                    "userVerification": "required"
                }
            }
        }));
        
        // Minimum requirements
        data.insert("minimum_requirements", json!({
            "description": "Request with minimum required fields",
            "request": {
                "username": "alice",
                "displayName": "Alice Smith"
            }
        }));
        
        data
    }
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_attestation_options_request_generation() {
        let request = TestDataFactory::attestation_options_request(
            Some("testuser"),
            Some("Test User"),
            Some("none")
        );
        
        assert_eq!(request["username"], "testuser");
        assert_eq!(request["displayName"], "Test User");
        assert_eq!(request["attestation"], "none");
    }

    #[test]
    fn test_attestation_result_request_generation() {
        let request = TestDataFactory::attestation_result_request(
            Some("test_credential_id"),
            Some("test_challenge"),
            Some("https://test.com")
        );
        
        assert_eq!(request["id"], "test_credential_id");
        assert_eq!(request["rawId"], "test_credential_id");
        assert_eq!(request["type"], "public-key");
    }

    #[test]
    fn test_random_generation() {
        let challenge1 = TestDataFactory::random_challenge();
        let challenge2 = TestDataFactory::random_challenge();
        
        assert_ne!(challenge1, challenge2);
        assert!(challenge1.len() >= 32);
        
        let cred_id1 = TestDataFactory::random_credential_id();
        let cred_id2 = TestDataFactory::random_credential_id();
        
        assert_ne!(cred_id1, cred_id2);
        assert!(cred_id1.len() >= 32);
    }

    #[test]
    fn test_security_test_vectors() {
        let vectors = TestDataFactory::security_test_vectors();
        
        assert!(vectors.contains_key("replay_attack"));
        assert!(vectors.contains_key("origin_mismatch"));
        assert!(vectors.contains_key("invalid_signature"));
        assert!(vectors.contains_key("truncated_data"));
        
        let replay_vector = &vectors["replay_attack"];
        assert!(replay_vector.get("description").is_some());
        assert!(replay_vector.get("request").is_some());
    }

    #[test]
    fn test_performance_test_data() {
        let data = TestDataFactory::performance_test_data();
        
        assert!(data.contains_key("concurrent_registration"));
        assert!(data.contains_key("concurrent_authentication"));
        assert!(data.contains_key("large_batch"));
        
        let concurrent_reg = &data["concurrent_registration"];
        assert_eq!(concurrent_reg.len(), 100);
        
        let large_batch = &data["large_batch"];
        assert_eq!(large_batch.len(), 1000);
    }

    #[test]
    fn test_compliance_test_data() {
        let data = TestDataFactory::compliance_test_data();
        
        assert!(data.contains_key("all_algorithms"));
        assert!(data.contains_key("resident_key"));
        assert!(data.contains_key("user_verification_required"));
        assert!(data.contains_key("minimum_requirements"));
        
        let algorithms = &data["all_algorithms"];
        let params = algorithms["request"]["pubKeyCredParams"].as_array().unwrap();
        assert_eq!(params.len(), 4);
    }
}