//! Test fixtures and data factories

use crate::common::create_test_webauthn_service;
use fido2_webauthn_server::schema::*;
use serde_json::json;

/// Factory for creating valid registration requests
pub struct RegistrationRequestFactory;

impl RegistrationRequestFactory {
    /// Create a valid registration request
    pub fn valid() -> ServerPublicKeyCredentialCreationOptionsRequest {
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

    /// Create a registration request with empty username
    pub fn empty_username() -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: Some("none".to_string()),
        }
    }

    /// Create a registration request with invalid attestation
    pub fn invalid_attestation() -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: "testuser@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: Some("invalid".to_string()),
        }
    }

    /// Create a registration request with long username
    pub fn long_username() -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: "a".repeat(65), // Exceeds 64 char limit
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: Some("none".to_string()),
        }
    }
}

/// Factory for creating valid authentication requests
pub struct AuthenticationRequestFactory;

impl AuthenticationRequestFactory {
    /// Create a valid authentication request
    pub fn valid() -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: Some("testuser@example.com".to_string()),
            user_verification: Some("preferred".to_string()),
        }
    }

    /// Create an authentication request with invalid user verification
    pub fn invalid_user_verification() -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: Some("testuser@example.com".to_string()),
            user_verification: Some("invalid".to_string()),
        }
    }

    /// Create an authentication request without username
    pub fn no_username() -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: None,
            user_verification: Some("required".to_string()),
        }
    }
}

/// Factory for creating attestation responses
pub struct AttestationResponseFactory;

impl AttestationResponseFactory {
    /// Create a valid attestation response
    pub fn valid() -> ServerPublicKeyCredentialAttestationResponse {
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

    /// Create an attestation response with empty ID
    pub fn empty_id() -> ServerPublicKeyCredentialAttestationResponse {
        ServerPublicKeyCredentialAttestationResponse {
            id: "".to_string(),
            raw_id: generate_test_credential_id(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: create_test_client_data_json("webauthn.create"),
                attestation_object: create_test_attestation_object(),
            },
            cred_type: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }

    /// Create an attestation response with invalid type
    pub fn invalid_type() -> ServerPublicKeyCredentialAttestationResponse {
        ServerPublicKeyCredentialAttestationResponse {
            id: generate_test_credential_id(),
            raw_id: generate_test_credential_id(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: create_test_client_data_json("webauthn.create"),
                attestation_object: create_test_attestation_object(),
            },
            cred_type: "invalid-type".to_string(),
            get_client_extension_results: None,
        }
    }

    /// Create an attestation response with invalid client data
    pub fn invalid_client_data() -> ServerPublicKeyCredentialAttestationResponse {
        ServerPublicKeyCredentialAttestationResponse {
            id: generate_test_credential_id(),
            raw_id: generate_test_credential_id(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: "invalid_base64+".to_string(),
                attestation_object: create_test_attestation_object(),
            },
            cred_type: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }
}

/// Factory for creating assertion responses
pub struct AssertionResponseFactory;

impl AssertionResponseFactory {
    /// Create a valid assertion response
    pub fn valid() -> ServerPublicKeyCredentialAssertionResponse {
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

    /// Create an assertion response with empty ID
    pub fn empty_id() -> ServerPublicKeyCredentialAssertionResponse {
        ServerPublicKeyCredentialAssertionResponse {
            id: "".to_string(),
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

    /// Create an assertion response with invalid authenticator data
    pub fn invalid_authenticator_data() -> ServerPublicKeyCredentialAssertionResponse {
        ServerPublicKeyCredentialAssertionResponse {
            id: generate_test_credential_id(),
            raw_id: generate_test_credential_id(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "short".to_string(), // Too short
                client_data_json: create_test_client_data_json("webauthn.get"),
                signature: create_test_signature(),
                user_handle: Some(generate_test_user_id()),
            },
            cred_type: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }

    /// Create an assertion response with empty signature
    pub fn empty_signature() -> ServerPublicKeyCredentialAssertionResponse {
        ServerPublicKeyCredentialAssertionResponse {
            id: generate_test_credential_id(),
            raw_id: generate_test_credential_id(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: create_test_authenticator_data(),
                client_data_json: create_test_client_data_json("webauthn.get"),
                signature: "".to_string(),
                user_handle: Some(generate_test_user_id()),
            },
            cred_type: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }
}

/// Generate a test credential ID
pub fn generate_test_credential_id() -> String {
    use rand::RngCore;
    let mut cred_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut cred_id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id)
}

/// Generate a test user ID
pub fn generate_test_user_id() -> String {
    use rand::RngCore;
    let mut user_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut user_id);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id)
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
    let attestation = json!({
        "fmt": "none",
        "attStmt": {},
        "authData": create_test_authenticator_data()
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation.to_string())
}

/// Create test authenticator data
pub fn create_test_authenticator_data() -> String {
    let mut auth_data = vec![0u8; 37]; // Minimum size
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