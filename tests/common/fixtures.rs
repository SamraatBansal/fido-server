//! Test fixtures and utilities

use serde_json::json;
use crate::webauthn_types::*;

/// Create a test registration request
pub fn create_test_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
        }),
        attestation: "direct".to_string(),
    }
}

/// Create a test authentication request
pub fn create_test_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
    ServerPublicKeyCredentialGetOptionsRequest {
        username: "test@example.com".to_string(),
        user_verification: Some("required".to_string()),
    }
}

/// Create a mock credential for testing
pub fn create_mock_credential(challenge: &str) -> ServerPublicKeyCredential {
    ServerPublicKeyCredential {
        id: "test_credential_id".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: create_mock_client_data_json(challenge, "webauthn.create"),
            attestation_object: "mock_attestation_object".to_string(),
        },
        get_client_extension_results: std::collections::HashMap::new(),
    }
}

/// Create a mock assertion credential for testing
pub fn create_mock_assertion_credential(challenge: &str) -> crate::webauthn_types::ServerAssertionPublicKeyCredential {
    crate::webauthn_types::ServerAssertionPublicKeyCredential {
        id: "test_credential_id".to_string(),
        cred_type: "public-key".to_string(),
        response: crate::webauthn_types::ServerAuthenticatorAssertionResponse {
            authenticator_data: "mock_authenticator_data".to_string(),
            signature: "mock_signature".to_string(),
            user_handle: "".to_string(),
            client_data_json: create_mock_client_data_json(challenge, "webauthn.get"),
        },
        get_client_extension_results: std::collections::HashMap::new(),
    }
}

/// Create mock client data JSON
fn create_mock_client_data_json(challenge: &str, ceremony_type: &str) -> String {
    let client_data = json!({
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "type": ceremony_type,
        "clientExtensions": {},
        "hashAlgorithm": "SHA-256"
    });
    
    base64::encode(client_data.to_string())
}