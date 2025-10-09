//! Test helpers and fixtures for WebAuthn testing

use crate::schema::*;
use serde_json::json;
use uuid::Uuid;

/// Create a test registration options request
pub fn create_test_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "testuser@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            user_verification: Some("preferred".to_string()),
            authenticator_attachment: Some("cross-platform".to_string()),
        }),
        attestation: Some("direct".to_string()),
    }
}

/// Create a test authentication options request
pub fn create_test_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
    ServerPublicKeyCredentialGetOptionsRequest {
        username: Some("testuser@example.com".to_string()),
        user_verification: Some("preferred".to_string()),
    }
}

/// Create a valid attestation response for testing
pub fn create_valid_attestation_response() -> ServerPublicKeyCredentialAttestationResponse {
    ServerPublicKeyCredentialAttestationResponse {
        id: generate_test_credential_id(),
        raw_id: generate_test_credential_id(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: create_test_client_data_json("webauthn.create"),
            attestation_object: create_test_attestation_object(),
        },
        cred_type: "public-key".to_string(),
        get_client_extension_results: None,
    }
}

/// Create a valid assertion response for testing
pub fn create_valid_assertion_response() -> ServerPublicKeyCredentialAssertionResponse {
    ServerPublicKeyCredentialAssertionResponse {
        id: generate_test_credential_id(),
        raw_id: generate_test_credential_id(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: create_test_authenticator_data(),
            client_data_json: create_test_client_data_json("webauthn.get"),
            signature: create_test_signature(),
            user_handle: Some(generate_test_user_id()),
        },
        cred_type: "public-key".to_string(),
        get_client_extension_results: None,
    }
}

/// Create test client data JSON
pub fn create_test_client_data_json(typ: &str) -> String {
    let client_data = json!({
        "type": typ,
        "challenge": generate_test_challenge(),
        "origin": "https://localhost:8080",
        "crossOrigin": false
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string())
}

/// Create test attestation object
pub fn create_test_attestation_object() -> String {
    // This is a minimal CBOR-encoded attestation object for testing
    // In real implementation, this would be properly formatted CBOR
    let attestation = json!({
        "fmt": "none",
        "attStmt": {},
        "authData": create_test_authenticator_data()
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation.to_string())
}

/// Create test authenticator data
pub fn create_test_authenticator_data() -> String {
    // 37 bytes minimum: rp_id_hash (32) + flags (1) + counter (4)
    let mut auth_data = vec![0u8; 37];
    // Fill with random data for testing
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut auth_data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth_data)
}

/// Create test signature
pub fn create_test_signature() -> String {
    let mut signature = vec![0u8; 64]; // Typical ECDSA signature size
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut signature);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
}

/// Generate test challenge
pub fn generate_test_challenge() -> String {
    use rand::RngCore;
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
}

/// Generate test credential ID
pub fn generate_test_credential_id() -> String {
    use rand::RngCore;
    let mut cred_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut cred_id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id)
}

/// Generate test user ID
pub fn generate_test_user_id() -> String {
    use rand::RngCore;
    let mut user_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut user_id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id)
}

/// Create invalid attestation response (for negative testing)
pub fn create_invalid_attestation_response() -> ServerPublicKeyCredentialAttestationResponse {
    ServerPublicKeyCredentialAttestationResponse {
        id: "".to_string(), // Invalid empty ID
        raw_id: "invalid+base64".to_string(), // Invalid base64
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: "invalid_json".to_string(),
            attestation_object: "".to_string(), // Empty attestation
        },
        cred_type: "invalid-type".to_string(), // Invalid type
        get_client_extension_results: None,
    }
}

/// Create invalid assertion response (for negative testing)
pub fn create_invalid_assertion_response() -> ServerPublicKeyCredentialAssertionResponse {
    ServerPublicKeyCredentialAssertionResponse {
        id: "".to_string(), // Invalid empty ID
        raw_id: "invalid+base64".to_string(), // Invalid base64
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "short".to_string(), // Too short
            client_data_json: "invalid_json".to_string(),
            signature: "".to_string(), // Empty signature
            user_handle: None,
        },
        cred_type: "invalid-type".to_string(), // Invalid type
        get_client_extension_results: None,
    }
}

/// Create registration request with invalid username
pub fn create_invalid_username_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "".to_string(), // Invalid empty username
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: Some("invalid".to_string()), // Invalid attestation
    }
}

/// Create authentication request with invalid user verification
pub fn create_invalid_user_verification_request() -> ServerPublicKeyCredentialGetOptionsRequest {
    ServerPublicKeyCredentialGetOptionsRequest {
        username: Some("testuser@example.com".to_string()),
        user_verification: Some("invalid".to_string()), // Invalid user verification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_test_registration_request() {
        let request = create_test_registration_request();
        assert!(request.validate().is_ok(), "Test registration request should be valid");
    }

    #[test]
    fn test_create_test_authentication_request() {
        let request = create_test_authentication_request();
        assert!(request.validate().is_ok(), "Test authentication request should be valid");
    }

    #[test]
    fn test_create_valid_attestation_response() {
        let response = create_valid_attestation_response();
        assert!(response.validate().is_ok(), "Test attestation response should be valid");
    }

    #[test]
    fn test_create_valid_assertion_response() {
        let response = create_valid_assertion_response();
        assert!(response.validate().is_ok(), "Test assertion response should be valid");
    }

    #[test]
    fn test_create_invalid_responses() {
        let invalid_attestation = create_invalid_attestation_response();
        assert!(invalid_attestation.validate().is_err(), "Invalid attestation should fail validation");

        let invalid_assertion = create_invalid_assertion_response();
        assert!(invalid_assertion.validate().is_err(), "Invalid assertion should fail validation");
    }

    #[test]
    fn test_create_invalid_requests() {
        let invalid_reg_request = create_invalid_username_request();
        assert!(invalid_reg_request.validate().is_err(), "Invalid registration request should fail validation");

        let invalid_auth_request = create_invalid_user_verification_request();
        assert!(invalid_auth_request.validate().is_err(), "Invalid authentication request should fail validation");
    }
}