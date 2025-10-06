//! Comprehensive Test Suite for FIDO2/WebAuthn Relying Party Server
//! 
//! This test suite provides complete coverage for:
//! - Unit tests for all modules
//! - Integration tests for API endpoints
//! - Security tests for FIDO2 compliance
//! - Performance tests for load testing
//! - Compliance tests for WebAuthn specification

pub mod common;
pub mod unit;
pub mod integration;
pub mod security;
pub mod performance;
pub mod compliance;

use common::test_setup::*;

// Test configuration constants
pub const TEST_RP_ID: &str = "localhost";
pub const TEST_RP_NAME: &str = "FIDO Test Server";
pub const TEST_ORIGIN: &str = "https://localhost:8443";

// Test data factories
pub mod factories {
    use base64::{Engine as _, engine::general_purpose};
    use serde_json::json;
    use uuid::Uuid;
    
    /// Generate valid base64url-encoded challenge (32 bytes)
    pub fn generate_challenge() -> String {
        let bytes: [u8; 32] = rand::random();
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    
    /// Generate valid base64url-encoded user ID (16 bytes)
    pub fn generate_user_id() -> String {
        let uuid = Uuid::new_v4();
        general_purpose::URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }
    
    /// Create valid attestation options request
    pub fn valid_attestation_options_request() -> serde_json::Value {
        json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        })
    }
    
    /// Create valid assertion options request
    pub fn valid_assertion_options_request() -> serde_json::Value {
        json!({
            "username": "test@example.com",
            "userVerification": "preferred"
        })
    }
    
    /// Create valid attestation result request
    pub fn valid_attestation_result_request() -> serde_json::Value {
        json!({
            "id": generate_credential_id(),
            "rawId": generate_credential_id(),
            "response": {
                "attestationObject": generate_base64url_data(300),
                "clientDataJSON": generate_client_data_json("webauthn.create")
            },
            "type": "public-key"
        })
    }
    
    /// Create valid assertion result request
    pub fn valid_assertion_result_request() -> serde_json::Value {
        json!({
            "id": generate_credential_id(),
            "rawId": generate_credential_id(),
            "response": {
                "authenticatorData": generate_base64url_data(37),
                "clientDataJSON": generate_client_data_json("webauthn.get"),
                "signature": generate_base64url_data(64),
                "userHandle": generate_user_id()
            },
            "type": "public-key"
        })
    }
    
    /// Generate credential ID
    pub fn generate_credential_id() -> String {
        let bytes: [u8; 16] = rand::random();
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    
    /// Generate base64url-encoded data of specified size
    pub fn generate_base64url_data(size: usize) -> String {
        let mut bytes = vec![0u8; size];
        rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    
    /// Generate valid clientDataJSON
    pub fn generate_client_data_json(type_: &str) -> String {
        let client_data = json!({
            "type": type_,
            "challenge": generate_challenge(),
            "origin": crate::TEST_ORIGIN,
            "crossOrigin": false
        });
        general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string())
    }
    
    // Invalid data factories for negative testing
    pub mod invalid {
        use super::*;
        
        /// Missing required field in attestation options
        pub fn attestation_options_missing_username() -> serde_json::Value {
            json!({
                "displayName": "Test User",
                "attestation": "direct"
            })
        }
        
        /// Invalid email format
        pub fn attestation_options_invalid_email() -> serde_json::Value {
            json!({
                "username": "invalid-email",
                "displayName": "Test User",
                "attestation": "direct"
            })
        }
        
        /// Oversized payload
        pub fn oversized_display_name() -> serde_json::Value {
            let oversized_name = "a".repeat(300);
            json!({
                "username": "test@example.com",
                "displayName": oversized_name,
                "attestation": "direct"
            })
        }
        
        /// Invalid base64url in attestation result
        pub fn attestation_result_invalid_base64() -> serde_json::Value {
            json!({
                "id": generate_credential_id(),
                "rawId": generate_credential_id(),
                "response": {
                    "attestationObject": "invalid-base64!@#",
                    "clientDataJSON": generate_client_data_json("webauthn.create")
                },
                "type": "public-key"
            })
        }
        
        /// Missing response in attestation result
        pub fn attestation_result_missing_response() -> serde_json::Value {
            json!({
                "id": generate_credential_id(),
                "rawId": generate_credential_id(),
                "type": "public-key"
            })
        }
        
        /// Invalid credential type
        pub fn invalid_credential_type() -> serde_json::Value {
            json!({
                "id": generate_credential_id(),
                "rawId": generate_credential_id(),
                "response": {
                    "attestationObject": generate_base64url_data(300),
                    "clientDataJSON": generate_client_data_json("webauthn.create")
                },
                "type": "invalid-type"
            })
        }
        
        /// Empty challenge
        pub fn empty_challenge() -> String {
            "".to_string()
        }
        
        /// Too short challenge
        pub fn short_challenge() -> String {
            general_purpose::URL_SAFE_NO_PAD.encode(&[1u8; 16])
        }
        
        /// Too long challenge
        pub fn long_challenge() -> String {
            general_purpose::URL_SAFE_NO_PAD.encode(&[1u8; 64])
        }
    }
}

// Test utilities
pub mod utils {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    
    /// Get current timestamp for testing
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    /// Generate timestamp in the past (for expired challenges)
    pub fn past_timestamp(seconds_ago: u64) -> u64 {
        current_timestamp() - seconds_ago
    }
    
    /// Generate timestamp in the future
    pub fn future_timestamp(seconds_ahead: u64) -> u64 {
        current_timestamp() + seconds_ahead
    }
    
    /// Sleep for specified duration (useful for timing tests)
    pub async fn sleep(duration_ms: u64) {
        tokio::time::sleep(Duration::from_millis(duration_ms)).await;
    }
    
    /// Validate base64url format
    pub fn is_valid_base64url(input: &str) -> bool {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).is_ok()
    }
    
    /// Extract challenge from clientDataJSON
    pub fn extract_challenge_from_client_data(client_data_json: &str) -> Option<String> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(client_data_json).ok()?;
        let json_str = String::from_utf8(decoded).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&json_str).ok()?;
        parsed.get("challenge")?.as_str().map(|s| s.to_string())
    }
}

// Test macros for common patterns
#[macro_export]
macro_rules! assert_valid_base64url {
    ($input:expr) => {
        assert!(
            $crate::utils::is_valid_base64url($input),
            "Expected valid base64url: {}",
            $input
        );
    };
}

#[macro_export]
macro_rules! assert_invalid_base64url {
    ($input:expr) => {
        assert!(
            !$crate::utils::is_valid_base64url($input),
            "Expected invalid base64url: {}",
            $input
        );
    };
}

#[macro_export]
macro_rules! assert_challenge_length {
    ($challenge:expr) => {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode($challenge).unwrap();
        assert_eq!(decoded.len(), 32, "Challenge must be exactly 32 bytes");
    };
}

#[macro_export]
macro_rules! assert_user_id_length {
    ($user_id:expr) => {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode($user_id).unwrap();
        assert_eq!(decoded.len(), 16, "User ID must be exactly 16 bytes");
    };
}