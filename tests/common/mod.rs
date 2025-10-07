//! Common testing utilities and helpers for FIDO2/WebAuthn tests

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use webauthn_rs::prelude::*;

/// Test configuration constants
pub mod constants {
    pub const TEST_RP_ID: &str = "localhost";
    pub const TEST_RP_NAME: &str = "Test FIDO Server";
    pub const TEST_RP_ORIGIN: &str = "https://localhost:8443";
    pub const TEST_USERNAME: &str = "test@example.com";
    pub const TEST_DISPLAY_NAME: &str = "Test User";
    pub const CHALLENGE_TIMEOUT_MS: u64 = 60000;
    pub const MAX_CREDENTIALS_PER_USER: usize = 10;
}

/// Test data factories for generating valid and invalid test data
pub mod factories {
    use super::*;
    use fake::{Fake, Faker};
    use rand::Rng;

    /// Generate a valid base64url-encoded challenge
    pub fn generate_challenge() -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a valid user ID
    pub fn generate_user_id() -> String {
        let uuid = Uuid::new_v4();
        general_purpose::URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }

    /// Generate a valid credential ID
    pub fn generate_credential_id() -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 64];
        rng.fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate valid attestation options request
    pub fn create_attestation_options_request() -> serde_json::Value {
        serde_json::json!({
            "username": constants::TEST_USERNAME,
            "displayName": constants::TEST_DISPLAY_NAME,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }

    /// Generate valid assertion options request
    pub fn create_assertion_options_request() -> serde_json::Value {
        serde_json::json!({
            "username": constants::TEST_USERNAME,
            "userVerification": "preferred"
        })
    }

    /// Generate valid attestation result request
    pub fn create_attestation_result_request() -> serde_json::Value {
        serde_json::json!({
            "id": generate_credential_id(),
            "rawId": generate_credential_id(),
            "response": {
                "attestationObject": generate_fake_attestation_object(),
                "clientDataJSON": generate_fake_client_data_json("webauthn.create")
            },
            "type": "public-key"
        })
    }

    /// Generate valid assertion result request
    pub fn create_assertion_result_request() -> serde_json::Value {
        serde_json::json!({
            "id": generate_credential_id(),
            "rawId": generate_credential_id(),
            "response": {
                "authenticatorData": generate_fake_authenticator_data(),
                "clientDataJSON": generate_fake_client_data_json("webauthn.get"),
                "signature": generate_fake_signature(),
                "userHandle": generate_user_id()
            },
            "type": "public-key"
        })
    }

    /// Generate fake attestation object (base64url encoded)
    fn generate_fake_attestation_object() -> String {
        // This would normally be a valid CBOR-encoded attestation object
        // For testing, we'll use a placeholder that looks valid
        let fake_data = vec![0xa3, 0x67, 0x66, 0x6d, 0x74, 0x01]; // CBOR prefix
        general_purpose::URL_SAFE_NO_PAD.encode(fake_data)
    }

    /// Generate fake client data JSON (base64url encoded)
    fn generate_fake_client_data_json(type_str: &str) -> String {
        let client_data = serde_json::json!({
            "type": type_str,
            "challenge": generate_challenge(),
            "origin": constants::TEST_RP_ORIGIN,
            "crossOrigin": false
        });
        general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string())
    }

    /// Generate fake authenticator data (base64url encoded)
    fn generate_fake_authenticator_data() -> String {
        let fake_data = vec![0x49, 0x96, 0x02, 0xd2]; // RP ID hash prefix
        general_purpose::URL_SAFE_NO_PAD.encode(fake_data)
    }

    /// Generate fake signature (base64url encoded)
    fn generate_fake_signature() -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 64];
        rng.fill(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate invalid base64url string
    pub fn create_invalid_base64url() -> String {
        "invalid!base64@url#encoding".to_string()
    }

    /// Generate oversized payload
    pub fn create_oversized_payload() -> String {
        "x".repeat(1_000_000) // 1MB string
    }
}

/// Custom test assertions for WebAuthn validation
pub mod assertions {
    use super::*;
    use serde_json::Value;

    /// Assert that a response contains required fields for attestation options
    pub fn assert_attestation_options_response(response: &Value) {
        assert!(response.get("challenge").is_some(), "Missing challenge field");
        assert!(response.get("rp").is_some(), "Missing rp field");
        assert!(response.get("user").is_some(), "Missing user field");
        assert!(response.get("pubKeyCredParams").is_some(), "Missing pubKeyCredParams field");
        assert!(response.get("timeout").is_some(), "Missing timeout field");
        assert!(response.get("attestation").is_some(), "Missing attestation field");

        // Validate RP structure
        let rp = response.get("rp").unwrap();
        assert_eq!(rp.get("name").unwrap().as_str().unwrap(), constants::TEST_RP_NAME);
        assert_eq!(rp.get("id").unwrap().as_str().unwrap(), constants::TEST_RP_ID);

        // Validate user structure
        let user = response.get("user").unwrap();
        assert!(user.get("id").is_some());
        assert_eq!(user.get("name").unwrap().as_str().unwrap(), constants::TEST_USERNAME);
        assert_eq!(user.get("displayName").unwrap().as_str().unwrap(), constants::TEST_DISPLAY_NAME);
    }

    /// Assert that a response contains required fields for assertion options
    pub fn assert_assertion_options_response(response: &Value) {
        assert!(response.get("challenge").is_some(), "Missing challenge field");
        assert!(response.get("rpId").is_some(), "Missing rpId field");
        assert!(response.get("allowCredentials").is_some(), "Missing allowCredentials field");
        assert!(response.get("timeout").is_some(), "Missing timeout field");
        assert!(response.get("userVerification").is_some(), "Missing userVerification field");

        // Validate RP ID
        assert_eq!(
            response.get("rpId").unwrap().as_str().unwrap(),
            constants::TEST_RP_ID
        );
    }

    /// Assert that a response contains required fields for attestation result
    pub fn assert_attestation_result_response(response: &Value) {
        assert!(response.get("status").is_some(), "Missing status field");
        assert!(response.get("errorMessage").is_some(), "Missing errorMessage field");
    }

    /// Assert that a response contains required fields for assertion result
    pub fn assert_assertion_result_response(response: &Value) {
        assert!(response.get("status").is_some(), "Missing status field");
        assert!(response.get("errorMessage").is_some(), "Missing errorMessage field");
    }

    /// Assert that a challenge is valid base64url and proper length
    pub fn assert_valid_challenge(challenge: &str) {
        assert!(!challenge.is_empty(), "Challenge should not be empty");
        
        // Test base64url decoding
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(challenge.as_bytes())
            .expect("Challenge should be valid base64url");
        
        assert_eq!(decoded.len(), 32, "Challenge should be 32 bytes");
    }

    /// Assert that a credential ID is valid base64url
    pub fn assert_valid_credential_id(credential_id: &str) {
        assert!(!credential_id.is_empty(), "Credential ID should not be empty");
        
        // Test base64url decoding
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(credential_id.as_bytes())
            .expect("Credential ID should be valid base64url");
        
        assert!(!decoded.is_empty(), "Credential ID should not be empty after decoding");
    }
}

/// Mock WebAuthn configuration for testing
pub mod mock_config {
    use super::*;
    use webauthn_rs::prelude::*;

    /// Create a test WebAuthn configuration
    pub fn create_test_webauthn() -> Webauthn {
        let rp = RelyingParty {
            id: constants::TEST_RP_ID.to_string(),
            name: constants::TEST_RP_NAME.to_string(),
            origin: Url::parse(constants::TEST_RP_ORIGIN).unwrap(),
        };

        Webauthn::new(rp)
    }

    /// Create test credential creation options
    pub fn create_test_credential_creation_options() -> PublicKeyCredentialCreationOptions {
        let user = User {
            id: factories::generate_user_id().into_bytes(),
            name: constants::TEST_USERNAME.to_string(),
            display_name: constants::TEST_DISPLAY_NAME.to_string(),
        };

        PublicKeyCredentialCreationOptions {
            rp: RelyingParty {
                id: constants::TEST_RP_ID.to_string(),
                name: constants::TEST_RP_NAME.to_string(),
                origin: Url::parse(constants::TEST_RP_ORIGIN).unwrap(),
            },
            user,
            challenge: factories::generate_challenge().into_bytes(),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::ES256,
                    type_: PublicKeyCredentialType::PublicKey,
                },
                PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::RS256,
                    type_: PublicKeyCredentialType::PublicKey,
                },
            ],
            timeout: Some(constants::CHALLENGE_TIMEOUT_MS),
            attestation: Some(AttestationConveyancePreference::Direct),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some(AuthenticatorAttachment::Platform),
                require_resident_key: false,
                user_verification: UserVerificationPolicy::Preferred,
            }),
        }
    }
}

/// Test error helpers
pub mod errors {
    use super::*;

    /// Common error scenarios for testing
    #[derive(Debug, Clone)]
    pub enum TestErrorScenario {
        MissingField(String),
        InvalidBase64Url(String),
        InvalidJson,
        OversizedPayload,
        InvalidChallenge,
        InvalidAttestation,
        InvalidSignature,
        ReplayAttack,
        CounterMismatch,
        UserNotFound,
        CredentialNotFound,
    }

    /// Create error request based on scenario
    pub fn create_error_request(scenario: TestErrorScenario) -> serde_json::Value {
        match scenario {
            TestErrorScenario::MissingField(field) => {
                let mut request = factories::create_attestation_options_request();
                if let Some(obj) = request.as_object_mut() {
                    obj.remove(&field);
                }
                request
            }
            TestErrorScenario::InvalidBase64Url(_) => {
                let mut request = factories::create_attestation_result_request();
                if let Some(response) = request.get_mut("response").unwrap().as_object_mut() {
                    response.insert("attestationObject".to_string(), 
                        serde_json::Value::String(factories::create_invalid_base64url()));
                }
                request
            }
            TestErrorScenario::InvalidJson => {
                serde_json::json!({"invalid": "json"})
            }
            TestErrorScenario::OversizedPayload => {
                serde_json::json!({
                    "username": factories::create_oversized_payload(),
                    "displayName": constants::TEST_DISPLAY_NAME
                })
            }
            _ => factories::create_attestation_options_request(),
        }
    }
}