//! Common test utilities, fixtures, and factories for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Test data factory for creating valid and invalid FIDO2 payloads
pub struct TestDataFactory;

impl TestDataFactory {
    /// Creates a valid attestation options request
    pub fn valid_attestation_options_request() -> Value {
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

    /// Creates a valid attestation options response
    pub fn valid_attestation_options_response() -> Value {
        json!({
            "challenge": URL_SAFE_NO_PAD.encode("valid-challenge-32-bytes-long-!!"),
            "rp": {
                "name": "Example RP",
                "id": "example.com"
            },
            "user": {
                "id": URL_SAFE_NO_PAD.encode("user-id-123"),
                "name": "alice@example.com",
                "displayName": "Alice Smith"
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                }
            ],
            "timeout": 60000,
            "attestation": "direct"
        })
    }

    /// Creates a valid attestation result request
    pub fn valid_attestation_result_request() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("fake-attestation-object"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"valid-challenge-32-bytes-long-!!\",\"origin\":\"https://example.com\"}")
            },
            "type": "public-key"
        })
    }

    /// Creates a valid assertion options request
    pub fn valid_assertion_options_request() -> Value {
        json!({
            "username": "alice@example.com",
            "userVerification": "preferred"
        })
    }

    /// Creates a valid assertion options response
    pub fn valid_assertion_options_response() -> Value {
        json!({
            "challenge": URL_SAFE_NO_PAD.encode("assertion-challenge-32-bytes-!!"),
            "rpId": "example.com",
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": URL_SAFE_NO_PAD.encode("credential-id-12345678")
                }
            ],
            "timeout": 60000,
            "userVerification": "preferred"
        })
    }

    /// Creates a valid assertion result request
    pub fn valid_assertion_result_request() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode("fake-authenticator-data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"assertion-challenge-32-bytes-!!\",\"origin\":\"https://example.com\"}"),
                "signature": URL_SAFE_NO_PAD.encode("fake-signature"),
                "userHandle": URL_SAFE_NO_PAD.encode("user-id-123")
            },
            "type": "public-key"
        })
    }

    // Invalid test data factories

    /// Creates attestation options request with missing username
    pub fn invalid_attestation_options_missing_username() -> Value {
        json!({
            "displayName": "Alice Smith",
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Creates attestation options request with invalid attestation value
    pub fn invalid_attestation_options_invalid_attestation() -> Value {
        json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith",
            "attestation": "invalid_value",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Creates attestation result request with malformed base64url
    pub fn invalid_attestation_result_malformed_base64() -> Value {
        json!({
            "id": "invalid-base64!@#",
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("fake-attestation-object"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
            },
            "type": "public-key"
        })
    }

    /// Creates attestation result request with missing response field
    pub fn invalid_attestation_result_missing_response() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "type": "public-key"
        })
    }

    /// Creates assertion result request with invalid signature
    pub fn invalid_assertion_result_invalid_signature() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode("fake-authenticator-data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"assertion-challenge-32-bytes-!!\",\"origin\":\"https://example.com\"}"),
                "signature": "invalid-signature",
                "userHandle": URL_SAFE_NO_PAD.encode("user-id-123")
            },
            "type": "public-key"
        })
    }

    /// Creates assertion result request with replayed challenge
    pub fn invalid_assertion_result_replayed_challenge() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode("fake-authenticator-data"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.get\",\"challenge\":\"old-expired-challenge\",\"origin\":\"https://example.com\"}"),
                "signature": URL_SAFE_NO_PAD.encode("fake-signature"),
                "userHandle": URL_SAFE_NO_PAD.encode("user-id-123")
            },
            "type": "public-key"
        })
    }

    /// Creates oversized payload (greater than 1MB)
    pub fn oversized_payload() -> Value {
        let large_string = "x".repeat(2_000_000); // 2MB string
        json!({
            "username": "alice@example.com",
            "displayName": &large_string,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Creates request with empty values
    pub fn empty_values_request() -> Value {
        json!({
            "username": "",
            "displayName": "",
            "attestation": "",
            "authenticatorSelection": {
                "authenticatorAttachment": "",
                "requireResidentKey": false,
                "userVerification": ""
            }
        })
    }

    /// Creates invalid base64url request
    pub fn invalid_base64url_request() -> Value {
        json!({
            "id": "invalid-base64!@#",
            "rawId": "invalid-base64!@#",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("fake-attestation-object"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\"}")
            },
            "type": "public-key"
        })
    }

    /// Creates oversized payload request
    pub fn oversized_payload_request() -> Value {
        let large_string = "x".repeat(2_000_000);
        json!({
            "username": "alice@example.com",
            "displayName": &large_string,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Creates FIDO2 compliant attestation response
    pub fn fido2_compliant_attestation_response() -> Value {
        json!({
            "challenge": URL_SAFE_NO_PAD.encode("valid-challenge-32-bytes-long-!!"),
            "rp": {
                "name": "Example RP",
                "id": "example.com"
            },
            "user": {
                "id": URL_SAFE_NO_PAD.encode("user-id-123"),
                "name": "alice@example.com",
                "displayName": "Alice Smith"
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ],
            "timeout": 60000,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }
}

/// Security test vectors for various attack scenarios
pub struct SecurityTestVectors;

impl SecurityTestVectors {
    /// Creates clientDataJSON with invalid origin
    pub fn client_data_invalid_origin() -> String {
        URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"valid-challenge-32-bytes-long-!!\",\"origin\":\"https://malicious.com\"}")
    }

    /// Creates clientDataJSON with mismatched challenge
    pub fn client_data_mismatched_challenge() -> String {
        URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"different-challenge-32-bytes-long-!!\",\"origin\":\"https://example.com\"}")
    }

    /// Creates clientDataJSON with invalid type
    pub fn client_data_invalid_type() -> String {
        URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.invalid\",\"challenge\":\"valid-challenge-32-bytes-long-!!\",\"origin\":\"https://example.com\"}")
    }

    /// Creates malformed CBOR data for attestation object
    pub fn malformed_cbor_attestation() -> String {
        URL_SAFE_NO_PAD.encode("invalid-cbor-data")
    }

    /// Creates truncated clientDataJSON
    pub fn truncated_client_data() -> String {
        URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"")
    }

    /// Creates attestation with invalid algorithm
    pub fn attestation_invalid_algorithm() -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "rawId": URL_SAFE_NO_PAD.encode("credential-id-12345678"),
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode("fake-attestation-with-invalid-alg"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode("{\"type\":\"webauthn.create\",\"challenge\":\"valid-challenge-32-bytes-long-!!\",\"origin\":\"https://example.com\"}")
            },
            "type": "public-key"
        })
    }
}

/// Test helper utilities
pub struct TestHelpers;

impl TestHelpers {
    /// Generates a random base64url string of specified length
    pub fn random_base64url(length: usize) -> String {
        let mut bytes = vec![0u8; length];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Creates a test timestamp
    pub fn test_timestamp() -> DateTime<Utc> {
        Utc::now()
    }

    /// Creates a test UUID
    pub fn test_uuid() -> Uuid {
        Uuid::new_v4()
    }

    /// Validates base64url string format
    pub fn is_valid_base64url(input: &str) -> bool {
        URL_SAFE_NO_PAD.decode(input).is_ok()
    }

    /// Creates test headers for HTTP requests
    pub fn test_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("User-Agent".to_string(), "FIDO-Test-Client/1.0".to_string());
        headers.insert("Origin".to_string(), "https://example.com".to_string());
        headers
    }
}

/// Performance test data generators
pub struct PerformanceTestData;

impl PerformanceTestData {
    /// Creates bulk user data for load testing
    pub fn bulk_users(count: usize) -> Vec<Value> {
        (0..count)
            .map(|i| json!({
                "username": format!("user{}@example.com", i),
                "displayName": format!("Test User {}", i),
                "attestation": "none",
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "requireResidentKey": false,
                    "userVerification": "preferred"
                }
            }))
            .collect()
    }

    /// Creates concurrent request data
    pub fn concurrent_requests(count: usize) -> Vec<Value> {
        (0..count)
            .map(|_| TestDataFactory::valid_attestation_options_request())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_attestation_options_request() {
        let request = TestDataFactory::valid_attestation_options_request();
        assert_eq!(request["username"], "alice@example.com");
        assert_eq!(request["displayName"], "Alice Smith");
        assert_eq!(request["attestation"], "direct");
    }

    #[test]
    fn test_base64url_validation() {
        let valid = TestHelpers::random_base64url(32);
        assert!(TestHelpers::is_valid_base64url(&valid));
        
        let invalid = "invalid-base64!@#";
        assert!(!TestHelpers::is_valid_base64url(invalid));
    }

    #[test]
    fn test_security_vectors() {
        let invalid_origin = SecurityTestVectors::client_data_invalid_origin();
        assert!(TestHelpers::is_valid_base64url(&invalid_origin));
        
        let malformed_cbor = SecurityTestVectors::malformed_cbor_attestation();
        assert!(TestHelpers::is_valid_base64url(&malformed_cbor));
    }

    #[test]
    fn test_performance_data_generation() {
        let users = PerformanceTestData::bulk_users(10);
        assert_eq!(users.len(), 10);
        
        for (i, user) in users.iter().enumerate() {
            assert_eq!(user["username"], format!("user{}@example.com", i));
        }
    }
}