//! Common test utilities and fixtures for FIDO2/WebAuthn testing
//! 
//! This module provides shared test infrastructure including:
//! - Test server setup and teardown
//! - Mock authenticator implementations
//! - Test data factories and fixtures
//! - Database test utilities

use serde_json::Value;
use std::sync::Once;
use uuid::Uuid;
use base64::Engine;
use webauthn_rp_server::dto::{
    attestation::*,
    assertion::*,
};

pub mod test_server;
pub mod test_data;
pub mod mock_authenticator;
pub mod test_database;

pub use test_server::*;
pub use test_data::*;
pub use mock_authenticator::*;
pub use test_database::*;

static INIT: Once = Once::new();

/// Initialize test environment (logging, etc.)
pub fn init_test_env() {
    INIT.call_once(|| {
        env_logger::init();
    });
}

/// Generate a random base64url-encoded challenge
pub fn generate_test_challenge() -> String {
    let mut challenge = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut challenge);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge)
}

/// Generate a random base64url-encoded credential ID
pub fn generate_test_credential_id() -> String {
    let mut id = vec![0u8; 64];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&id)
}

/// Generate a random base64url-encoded user ID
pub fn generate_test_user_id() -> String {
    let uuid = Uuid::new_v4();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uuid.as_bytes())
}

/// Test assertion helper for JSON responses
pub fn assert_json_response(response: &Value, expected_status: &str) {
    assert_eq!(
        response.get("status").and_then(|v| v.as_str()),
        Some(expected_status),
        "Response status mismatch. Full response: {}",
        serde_json::to_string_pretty(response).unwrap()
    );
}

/// Test assertion helper for error responses
pub fn assert_error_response(response: &Value, expected_error: &str) {
    assert_json_response(response, "failed");
    assert!(
        response.get("errorMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains(expected_error),
        "Error message mismatch. Expected: '{}', Got: '{}'",
        expected_error,
        response.get("errorMessage").and_then(|v| v.as_str()).unwrap_or("")
    );
}

/// Validate base64url encoding
pub fn is_valid_base64url(s: &str) -> bool {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).is_ok()
}

/// Validate challenge format and length
pub fn validate_challenge(challenge: &str) -> bool {
    if !is_valid_base64url(challenge) {
        return false;
    }
    
    if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge) {
        decoded.len() >= 16 && decoded.len() <= 64
    } else {
        false
    }
}

/// Validate credential ID format
pub fn validate_credential_id(id: &str) -> bool {
    is_valid_base64url(id) && !id.is_empty()
}

/// Validate user ID format
pub fn validate_user_id(id: &str) -> bool {
    is_valid_base64url(id) && !id.is_empty()
}

/// Test data validation helper
pub fn validate_attestation_options_response(response: &ServerPublicKeyCredentialCreationOptionsResponse) -> Result<(), String> {
    // Validate status
    if response.base.status != "ok" {
        return Err(format!("Invalid status: {}", response.base.status));
    }
    
    // Validate challenge
    if !validate_challenge(&response.challenge) {
        return Err(format!("Invalid challenge: {}", response.challenge));
    }
    
    // Validate RP
    if response.rp.name.is_empty() {
        return Err("RP name cannot be empty".to_string());
    }
    
    // Validate user
    if !validate_user_id(&response.user.id) {
        return Err(format!("Invalid user ID: {}", response.user.id));
    }
    
    if response.user.name.is_empty() {
        return Err("User name cannot be empty".to_string());
    }
    
    if response.user.display_name.is_empty() {
        return Err("User display name cannot be empty".to_string());
    }
    
    // Validate pubKeyCredParams
    if response.pub_key_cred_params.is_empty() {
        return Err("pubKeyCredParams cannot be empty".to_string());
    }
    
    for param in &response.pub_key_cred_params {
        if param.credential_type != "public-key" {
            return Err(format!("Invalid credential type: {}", param.credential_type));
        }
    }
    
    // Validate timeout
    if let Some(timeout) = response.timeout {
        if timeout == 0 || timeout > 300000 { // Max 5 minutes
            return Err(format!("Invalid timeout: {}", timeout));
        }
    }
    
    // Validate attestation
    if !["none", "indirect", "direct", "enterprise"].contains(&response.attestation.as_str()) {
        return Err(format!("Invalid attestation: {}", response.attestation));
    }
    
    Ok(())
}

/// Test data validation helper for assertion options response
pub fn validate_assertion_options_response(response: &ServerPublicKeyCredentialGetOptionsResponse) -> Result<(), String> {
    // Validate status
    if response.base.status != "ok" {
        return Err(format!("Invalid status: {}", response.base.status));
    }
    
    // Validate challenge
    if !validate_challenge(&response.challenge) {
        return Err(format!("Invalid challenge: {}", response.challenge));
    }
    
    // Validate RP ID
    if response.rp_id.is_empty() {
        return Err("RP ID cannot be empty".to_string());
    }
    
    // Validate allowCredentials
    for cred in &response.allow_credentials {
        if cred.credential_type != "public-key" {
            return Err(format!("Invalid credential type: {}", cred.credential_type));
        }
        
        if !validate_credential_id(&cred.id) {
            return Err(format!("Invalid credential ID: {}", cred.id));
        }
    }
    
    // Validate timeout
    if let Some(timeout) = response.timeout {
        if timeout == 0 || timeout > 300000 { // Max 5 minutes
            return Err(format!("Invalid timeout: {}", timeout));
        }
    }
    
    // Validate user verification
    if let Some(uv) = &response.user_verification {
        if !["required", "preferred", "discouraged"].contains(&uv.as_str()) {
            return Err(format!("Invalid user verification: {}", uv));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_challenge() {
        let challenge = generate_test_challenge();
        assert!(validate_challenge(&challenge));
        assert!(!challenge.is_empty());
    }

    #[test]
    fn test_generate_test_credential_id() {
        let id = generate_test_credential_id();
        assert!(validate_credential_id(&id));
        assert!(!id.is_empty());
    }

    #[test]
    fn test_generate_test_user_id() {
        let id = generate_test_user_id();
        assert!(validate_user_id(&id));
        assert!(!id.is_empty());
    }

    #[test]
    fn test_validate_challenge() {
        // Valid challenges
        assert!(validate_challenge("dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MA"));
        
        // Invalid challenges
        assert!(!validate_challenge(""));
        assert!(!validate_challenge("invalid-base64!"));
        assert!(!validate_challenge("dGVzdA")); // Too short
    }

    #[test]
    fn test_validate_credential_id() {
        // Valid credential IDs
        assert!(validate_credential_id("dGVzdC1jcmVkZW50aWFsLWlk"));
        
        // Invalid credential IDs
        assert!(!validate_credential_id(""));
        assert!(!validate_credential_id("invalid-base64!"));
    }

    #[test]
    fn test_validate_user_id() {
        // Valid user IDs
        assert!(validate_user_id("dGVzdC11c2VyLWlk"));
        
        // Invalid user IDs
        assert!(!validate_user_id(""));
        assert!(!validate_user_id("invalid-base64!"));
    }

    #[test]
    fn test_assert_json_response() {
        let response = json!({
            "status": "ok",
            "errorMessage": ""
        });
        
        assert_json_response(&response, "ok");
    }

    #[test]
    fn test_assert_error_response() {
        let response = json!({
            "status": "failed",
            "errorMessage": "Test error message"
        });
        
        assert_error_response(&response, "Test error");
    }

    #[test]
    fn test_is_valid_base64url() {
        assert!(is_valid_base64url("dGVzdA"));
        assert!(is_valid_base64url("dGVzdC1kYXRh"));
        assert!(!is_valid_base64url("invalid-base64!"));
        assert!(!is_valid_base64url("test+data")); // Standard base64, not URL-safe
    }
}