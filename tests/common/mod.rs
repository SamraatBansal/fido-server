//! Common test utilities and factories for FIDO2/WebAuthn testing

use serde_json::{json, Value};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Test data factory for WebAuthn API requests
pub struct WebAuthnTestDataFactory;

impl WebAuthnTestDataFactory {
    /// Create a valid attestation options request
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

    /// Create a valid attestation result request
    pub fn valid_attestation_result_request() -> Value {
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(b"test-credential-id");
        let attestation_object = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-attestation-object");
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"type":"webauthn.create","challenge":"test-challenge","origin":"https://example.com"}"#
        );

        json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "attestationObject": attestation_object,
                "clientDataJSON": client_data_json
            },
            "type": "public-key"
        })
    }

    /// Create a valid assertion options request
    pub fn valid_assertion_options_request() -> Value {
        json!({
            "username": "alice@example.com",
            "userVerification": "preferred"
        })
    }

    /// Create a valid assertion result request
    pub fn valid_assertion_result_request() -> Value {
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(b"test-credential-id");
        let authenticator_data = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-authenticator-data");
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"type":"webauthn.get","challenge":"test-challenge","origin":"https://example.com"}"#
        );
        let signature = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-signature");
        let user_handle = general_purpose::URL_SAFE_NO_PAD.encode(b"test-user-handle");

        json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "authenticatorData": authenticator_data,
                "clientDataJSON": client_data_json,
                "signature": signature,
                "userHandle": user_handle
            },
            "type": "public-key"
        })
    }

    /// Create invalid attestation options request (missing username)
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

    /// Create invalid attestation options request (invalid email)
    pub fn invalid_attestation_options_invalid_email() -> Value {
        json!({
            "username": "invalid-email",
            "displayName": "Alice Smith",
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Create malformed JSON request
    pub fn malformed_json_request() -> String {
        "{ invalid json }".to_string()
    }

    /// Create request with oversized payload
    pub fn oversized_payload_request() -> Value {
        let large_string = "x".repeat(10_000_000); // 10MB string
        json!({
            "username": "alice@example.com",
            "displayName": large_string,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Create request with invalid base64url
    pub fn invalid_base64url_request() -> Value {
        json!({
            "id": "invalid-base64!@#",
            "rawId": "invalid-base64!@#",
            "response": {
                "attestationObject": "invalid-base64!@#",
                "clientDataJSON": "invalid-base64!@#"
            },
            "type": "public-key"
        })
    }

    /// Create replay attack request (old challenge)
    pub fn replay_attack_request() -> Value {
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(b"test-credential-id");
        let attestation_object = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-attestation-object");
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"type":"webauthn.create","challenge":"old-expired-challenge","origin":"https://example.com"}"#
        );

        json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "attestationObject": attestation_object,
                "clientDataJSON": client_data_json
            },
            "type": "public-key"
        })
    }

    /// Create request with tampered clientDataJSON
    pub fn tampered_client_data_request() -> Value {
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(b"test-credential-id");
        let attestation_object = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-attestation-object");
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"type":"webauthn.create","challenge":"different-challenge","origin":"https://malicious.com"}"#
        );

        json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "attestationObject": attestation_object,
                "clientDataJSON": client_data_json
            },
            "type": "public-key"
        })
    }

    /// Create request with invalid RP ID
    pub fn invalid_rp_id_request() -> Value {
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(b"test-credential-id");
        let authenticator_data = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-authenticator-data");
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"type":"webauthn.get","challenge":"test-challenge","origin":"https://malicious.com"}"#
        );
        let signature = general_purpose::URL_SAFE_NO_PAD.encode(b"mock-signature");
        let user_handle = general_purpose::URL_SAFE_NO_PAD.encode(b"test-user-handle");

        json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "authenticatorData": authenticator_data,
                "clientDataJSON": client_data_json,
                "signature": signature,
                "userHandle": user_handle
            },
            "type": "public-key"
        })
    }
}

/// Test helper utilities
pub struct TestHelpers;

impl TestHelpers {
    /// Generate a random challenge for testing
    pub fn generate_test_challenge() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate a timestamp for testing
    pub fn generate_test_timestamp() -> DateTime<Utc> {
        Utc::now()
    }

    /// Create a mock user ID
    pub fn create_mock_user_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Create a mock credential ID
    pub fn create_mock_credential_id() -> Vec<u8> {
        Uuid::new_v4().as_bytes().to_vec()
    }

    /// Validate base64url string
    pub fn is_valid_base64url(input: &str) -> bool {
        general_purpose::URL_SAFE_NO_PAD.decode(input).is_ok()
    }

    /// Create test headers
    pub fn create_test_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("User-Agent".to_string(), "FIDO2-Test-Client/1.0".to_string());
        headers
    }
}

/// Security test vectors
pub struct SecurityTestVectors;

impl SecurityTestVectors {
    /// Malformed CBOR data
    pub fn malformed_cbor() -> Vec<u8> {
        vec![0x99, 0x99, 0x99, 0x99] // Invalid CBOR
    }

    /// Truncated clientDataJSON
    pub fn truncated_client_data_json() -> String {
        r#"{"type":"webauthn.create","challenge":"test-challenge","origin":"https://example.com""#.to_string()
    }

    /// Buffer overflow attempt
    pub fn buffer_overflow_attempt() -> Vec<u8> {
        vec![0; 1_000_000] // 1MB of zeros
    }

    /// SQL injection attempt
    pub fn sql_injection_attempt() -> String {
        "'; DROP TABLE users; --".to_string()
    }

    /// XSS attempt
    pub fn xss_attempt() -> String {
        "<script>alert('xss')</script>".to_string()
    }
}

/// Performance test configurations
pub struct PerformanceTestConfig;

impl PerformanceTestConfig {
    /// Number of concurrent requests for load testing
    pub const CONCURRENT_REQUESTS: usize = 100;
    
    /// Duration for stress testing (seconds)
    pub const STRESS_TEST_DURATION: u64 = 60;
    
    /// Payload size for performance testing (bytes)
    pub const PERFORMANCE_PAYLOAD_SIZE: usize = 1024;
}

/// Compliance test data
pub struct ComplianceTestData;

impl ComplianceTestData {
    /// FIDO2 compliant attestation options response
    pub fn fido2_compliant_attestation_response() -> Value {
        json!({
            "challenge": "BASE64URLSTRING",
            "rp": { 
                "name": "Example RP", 
                "id": "example.com" 
            },
            "user": { 
                "id": "BASE64URL", 
                "name": "alice", 
                "displayName": "Alice Smith" 
            },
            "pubKeyCredParams": [{ 
                "type": "public-key", 
                "alg": -7 
            }],
            "timeout": 60000,
            "attestation": "direct"
        })
    }

    /// FIDO2 compliant assertion options response
    pub fn fido2_compliant_assertion_response() -> Value {
        json!({
            "challenge": "BASE64URLSTRING",
            "rpId": "example.com",
            "allowCredentials": [{ 
                "type": "public-key", 
                "id": "BASE64URL" 
            }],
            "timeout": 60000,
            "userVerification": "preferred"
        })
    }
}