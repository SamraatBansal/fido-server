//! Security test vectors for FIDO2/WebAuthn attack simulation
//!
//! This module provides test vectors for various security attacks and edge cases
//! to ensure the server properly validates and rejects malicious requests.

use serde_json::{json, Value};
use super::{base64url, data_factories::*};
use rand::{Rng, thread_rng};

/// Security attack vectors for testing
pub struct SecurityVectors;

impl SecurityVectors {
    /// Replay attack: reuse old challenge
    pub fn replay_attack_challenge() -> Value {
        // Use a fixed old challenge that should be rejected
        let old_challenge = "dGhpc19pc19hbl9vbGRfY2hhbGxlbmdl"; // "this_is_an_old_challenge" in base64url
        
        let mut request = AttestationResultRequestFactory::valid();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": old_challenge,
            "origin": "https://example.com",
            "crossOrigin": false
        });
        request["response"]["clientDataJSON"] = json!(base64url::encode(client_data.to_string().as_bytes()));
        request
    }
    
    /// Origin mismatch attack
    pub fn origin_mismatch_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": AttestationOptionsResponseFactory::generate_challenge(),
            "origin": "https://evil.com", // Wrong origin
            "crossOrigin": false
        });
        request["response"]["clientDataJSON"] = json!(base64url::encode(client_data.to_string().as_bytes()));
        request
    }
    
    /// RP ID mismatch attack
    pub fn rp_id_mismatch_attack() -> Value {
        // This would be used in assertion requests where rpId doesn't match expected
        let mut response = AssertionOptionsResponseFactory::valid();
        response["rpId"] = json!("evil.com");
        response
    }
    
    /// Malformed CBOR in attestation object
    pub fn malformed_cbor_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        // Invalid CBOR data
        request["response"]["attestationObject"] = json!("aW52YWxpZF9jYm9yX2RhdGE");
        request
    }
    
    /// Truncated client data JSON
    pub fn truncated_client_data_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        // Truncated base64url data
        request["response"]["clientDataJSON"] = json!("eyJjaGFsbGVuZ2UiOiJ"); // Incomplete
        request
    }
    
    /// Buffer overflow attempt with oversized payload
    pub fn buffer_overflow_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        // Extremely large attestation object
        let large_data = "A".repeat(1_000_000);
        request["response"]["attestationObject"] = json!(large_data);
        request
    }
    
    /// SQL injection attempt in username
    pub fn sql_injection_attack() -> Value {
        json!({
            "username": "'; DROP TABLE users; --",
            "displayName": "SQL Injection Attempt"
        })
    }
    
    /// XSS attempt in display name
    pub fn xss_attack() -> Value {
        json!({
            "username": "xss@example.com",
            "displayName": "<script>alert('XSS')</script>"
        })
    }
    
    /// Invalid base64url characters
    pub fn invalid_base64url_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        request["id"] = json!("invalid+base64/with=padding"); // Contains invalid chars for base64url
        request
    }
    
    /// Credential ID collision attack
    pub fn credential_collision_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        // Use a predictable/weak credential ID
        request["id"] = json!("AAAAAAAAAAAAAAAAAAAAAA"); // All zeros
        request["rawId"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
        request
    }
    
    /// Time-based attack with expired challenge
    pub fn expired_challenge_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        // Use a challenge that would be considered expired
        let expired_challenge = "ZXhwaXJlZF9jaGFsbGVuZ2U"; // "expired_challenge" in base64url
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": expired_challenge,
            "origin": "https://example.com",
            "crossOrigin": false
        });
        request["response"]["clientDataJSON"] = json!(base64url::encode(client_data.to_string().as_bytes()));
        request
    }
    
    /// Cross-origin attack
    pub fn cross_origin_attack() -> Value {
        let mut request = AttestationResultRequestFactory::valid();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": AttestationOptionsResponseFactory::generate_challenge(),
            "origin": "https://example.com",
            "crossOrigin": true // Should be false for same-origin
        });
        request["response"]["clientDataJSON"] = json!(base64url::encode(client_data.to_string().as_bytes()));
        request
    }
    
    /// Signature manipulation attack
    pub fn signature_manipulation_attack() -> Value {
        let mut request = AssertionResultRequestFactory::valid();
        // Flip bits in the signature
        let mut signature_bytes = base64url::decode(&AssertionResultRequestFactory::generate_signature()).unwrap();
        signature_bytes[0] ^= 0xFF; // Flip all bits in first byte
        request["response"]["signature"] = json!(base64url::encode(&signature_bytes));
        request
    }
    
    /// User handle manipulation attack
    pub fn user_handle_manipulation_attack() -> Value {
        let mut request = AssertionResultRequestFactory::valid();
        // Use a different user handle than expected
        request["response"]["userHandle"] = json!(base64url::encode(b"different_user"));
        request
    }
    
    /// Authenticator data manipulation attack
    pub fn authenticator_data_manipulation_attack() -> Value {
        let mut request = AssertionResultRequestFactory::valid();
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x00; // Clear user present flag (should be set)
        request["response"]["authenticatorData"] = json!(base64url::encode(&auth_data));
        request
    }
    
    /// Generate malformed JSON payloads
    pub fn malformed_json_payloads() -> Vec<String> {
        vec![
            "{".to_string(), // Incomplete JSON
            "{'username': 'test'}".to_string(), // Single quotes
            "{\"username\": }".to_string(), // Missing value
            "{\"username\": \"test\",}".to_string(), // Trailing comma
            "null".to_string(), // Null instead of object
            "[]".to_string(), // Array instead of object
            "\"string\"".to_string(), // String instead of object
            "{\"username\": \"test\", \"username\": \"duplicate\"}".to_string(), // Duplicate keys
        ]
    }
    
    /// Generate oversized payloads for DoS testing
    pub fn oversized_payloads() -> Vec<Value> {
        vec![
            // Oversized username
            json!({
                "username": "a".repeat(10_000),
                "displayName": "Test"
            }),
            // Oversized display name
            json!({
                "username": "test@example.com",
                "displayName": "a".repeat(10_000)
            }),
            // Oversized attestation object
            {
                let mut request = AttestationResultRequestFactory::valid();
                request["response"]["attestationObject"] = json!("A".repeat(100_000));
                request
            },
            // Oversized client data
            {
                let mut request = AttestationResultRequestFactory::valid();
                request["response"]["clientDataJSON"] = json!("A".repeat(100_000));
                request
            }
        ]
    }
    
    /// Generate boundary condition test cases
    pub fn boundary_conditions() -> Vec<Value> {
        vec![
            // Minimum length challenge
            {
                let challenge = base64url::encode(&[0u8; 16]); // 16 bytes minimum
                let mut response = AttestationOptionsResponseFactory::valid();
                response["challenge"] = json!(challenge);
                response
            },
            // Maximum length challenge
            {
                let challenge = base64url::encode(&[0u8; 64]); // 64 bytes maximum
                let mut response = AttestationOptionsResponseFactory::valid();
                response["challenge"] = json!(challenge);
                response
            },
            // Zero timeout
            {
                let mut response = AttestationOptionsResponseFactory::valid();
                response["timeout"] = json!(0);
                response
            },
            // Maximum timeout
            {
                let mut response = AttestationOptionsResponseFactory::valid();
                response["timeout"] = json!(u32::MAX);
                response
            }
        ]
    }
    
    /// Generate Unicode and encoding edge cases
    pub fn unicode_edge_cases() -> Vec<Value> {
        vec![
            // Unicode in username
            json!({
                "username": "用户@example.com",
                "displayName": "Unicode User"
            }),
            // Emoji in display name
            json!({
                "username": "emoji@example.com",
                "displayName": "🔐 Secure User 🛡️"
            }),
            // Mixed scripts
            json!({
                "username": "mixed@example.com",
                "displayName": "Mixed Αλφάβητο العربية 中文"
            }),
            // Zero-width characters
            json!({
                "username": "zero\u{200B}width@example.com",
                "displayName": "Zero\u{200C}Width\u{200D}User"
            }),
            // RTL override characters
            json!({
                "username": "rtl@example.com",
                "displayName": "RTL\u{202E}Override\u{202C}User"
            })
        ]
    }
}