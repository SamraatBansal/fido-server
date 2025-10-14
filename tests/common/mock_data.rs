//! Mock data and test scenarios for FIDO2/WebAuthn testing

use crate::common::fixtures::*;
use serde_json::json;

/// Mock attestation scenarios
pub mod attestation {
    use super::*;

    /// Valid Packed attestation
    pub fn valid_packed_attestation() -> ServerAuthenticatorAttestationResponse {
        ServerAuthenticatorAttestationResponse {
            client_data_json: valid_client_data_json_create(),
            attestation_object: valid_attestation_object(),
        }
    }

    /// Valid FIDO U2F attestation
    pub fn valid_fido_u2f_attestation() -> ServerAuthenticatorAttestationResponse {
        ServerAuthenticatorAttestationResponse {
            client_data_json: valid_client_data_json_create(),
            attestation_object: URL_SAFE_NO_PAD.encode(&[0xA3, 0x67, 0x66, 0x6D, 0x74, 0x01]), // Mock U2F format
        }
    }

    /// None attestation (no attestation data)
    pub fn none_attestation() -> ServerAuthenticatorAttestationResponse {
        ServerAuthenticatorAttestationResponse {
            client_data_json: valid_client_data_json_create(),
            attestation_object: URL_SAFE_NO_PAD.encode(&[0xA2, 0x67, 0x66, 0x6D, 0x74, 0x00]), // None format
        }
    }

    /// Invalid attestation (malformed CBOR)
    pub fn invalid_attestation() -> ServerAuthenticatorAttestationResponse {
        ServerAuthenticatorAttestationResponse {
            client_data_json: valid_client_data_json_create(),
            attestation_object: invalid_base64url(),
        }
    }

    /// Expired challenge in client data
    pub fn expired_challenge_attestation() -> ServerAuthenticatorAttestationResponse {
        let client_data = json!({
            "challenge": expired_challenge(),
            "origin": "https://example.com",
            "type": "webauthn.create",
            "clientExtensions": {}
        });
        ServerAuthenticatorAttestationResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            attestation_object: valid_attestation_object(),
        }
    }

    /// Wrong origin in client data
    pub fn wrong_origin_attestation() -> ServerAuthenticatorAttestationResponse {
        let client_data = json!({
            "challenge": valid_challenge(),
            "origin": "https://evil.com",
            "type": "webauthn.create",
            "clientExtensions": {}
        });
        ServerAuthenticatorAttestationResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            attestation_object: valid_attestation_object(),
        }
    }

    /// Wrong type in client data
    pub fn wrong_type_attestation() -> ServerAuthenticatorAttestationResponse {
        let client_data = json!({
            "challenge": valid_challenge(),
            "origin": "https://example.com",
            "type": "webauthn.get", // Wrong type for attestation
            "clientExtensions": {}
        });
        ServerAuthenticatorAttestationResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            attestation_object: valid_attestation_object(),
        }
    }
}

/// Mock assertion scenarios
pub mod assertion {
    use super::*;

    /// Valid assertion response
    pub fn valid_assertion() -> ServerAuthenticatorAssertionResponse {
        ServerAuthenticatorAssertionResponse {
            authenticator_data: valid_authenticator_data(),
            client_data_json: valid_client_data_json_get(),
            signature: valid_signature(),
            user_handle: valid_user_handle(),
        }
    }

    /// Invalid signature
    pub fn invalid_signature_assertion() -> ServerAuthenticatorAssertionResponse {
        ServerAuthenticatorAssertionResponse {
            authenticator_data: valid_authenticator_data(),
            client_data_json: valid_client_data_json_get(),
            signature: invalid_base64url(),
            user_handle: valid_user_handle(),
        }
    }

    /// Expired challenge
    pub fn expired_challenge_assertion() -> ServerAuthenticatorAssertionResponse {
        let client_data = json!({
            "challenge": expired_challenge(),
            "origin": "https://example.com",
            "type": "webauthn.get",
            "clientExtensions": {}
        });
        ServerAuthenticatorAssertionResponse {
            authenticator_data: valid_authenticator_data(),
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            signature: valid_signature(),
            user_handle: valid_user_handle(),
        }
    }

    /// Wrong RP ID in authenticator data
    pub fn wrong_rp_id_assertion() -> ServerAuthenticatorAssertionResponse {
        // Mock authenticator data with wrong RP ID hash
        let wrong_auth_data = vec![
            0x41, 0x96, 0x0D, 0xE5, 0x90, 0x38, 0x6F, 0x84, 0x31, 0x95, 0xCF, 0x6D,
            0xD5, 0x8C, 0xA4, 0x20, 0xAA, 0x06, 0x63, 0x8A, 0x62, 0x2F, 0x45, 0x61,
            0x2E, 0xC8, 0x15, 0x5A, 0x08, 0x10, 0x3A, 0x25, 0x82, 0x5A, 0xB2, 0x01,
            0x00, 0x00, 0x00
        ];
        ServerAuthenticatorAssertionResponse {
            authenticator_data: URL_SAFE_NO_PAD.encode(wrong_auth_data),
            client_data_json: valid_client_data_json_get(),
            signature: valid_signature(),
            user_handle: valid_user_handle(),
        }
    }

    /// User verification required but not provided
    pub fn missing_user_verification_assertion() -> ServerAuthenticatorAssertionResponse {
        // Authenticator data without user verified flag
        let auth_data_no_uv = vec![
            0x49, 0x96, 0x0D, 0xE5, 0x90, 0x38, 0x6F, 0x84, 0x31, 0x95, 0xCF, 0x6D,
            0xD5, 0x8C, 0xA4, 0x20, 0xAA, 0x06, 0x63, 0x8A, 0x62, 0x2F, 0x45, 0x61,
            0x2E, 0xC8, 0x15, 0x5A, 0x08, 0x10, 0x3A, 0x25, 0x82, 0x5A, 0xB2, 0x00, // UV flag not set
            0x00, 0x00, 0x00
        ];
        ServerAuthenticatorAssertionResponse {
            authenticator_data: URL_SAFE_NO_PAD.encode(auth_data_no_uv),
            client_data_json: valid_client_data_json_get(),
            signature: valid_signature(),
            user_handle: valid_user_handle(),
        }
    }
}

/// Mock request scenarios
pub mod requests {
    use super::*;

    /// Valid registration request
    pub fn valid_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
        create_valid_attestation_options_request()
    }

    /// Registration request with missing username
    pub fn missing_username_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(),
            display_name: "Alice Smith".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        }
    }

    /// Registration request with invalid attestation preference
    pub fn invalid_attestation_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: "alice@example.com".to_string(),
            display_name: "Alice Smith".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("invalid".to_string()), // Invalid attestation preference
        }
    }

    /// Valid authentication request
    pub fn valid_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
        create_valid_assertion_options_request()
    }

    /// Authentication request with missing username
    pub fn missing_username_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: "".to_string(),
            user_verification: Some("preferred".to_string()),
        }
    }

    /// Authentication request with invalid user verification
    pub fn invalid_user_verification_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: "alice@example.com".to_string(),
            user_verification: Some("invalid".to_string()), // Invalid user verification
        }
    }
}

/// Mock response scenarios
pub mod responses {
    use super::*;

    /// Successful attestation options response
    pub fn successful_attestation_options_response() -> ServerPublicKeyCredentialCreationOptionsResponse {
        ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: "Example Corporation".to_string(),
                id: Some("example.com".to_string()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: valid_user_id(),
                name: "alice@example.com".to_string(),
                display_name: "Alice Smith".to_string(),
            },
            challenge: valid_challenge(),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
            ],
            timeout: Some(60000),
            exclude_credentials: Some(vec![]),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
            extensions: Some(json!({})),
        }
    }

    /// Successful assertion options response
    pub fn successful_assertion_options_response() -> ServerPublicKeyCredentialGetOptionsResponse {
        ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: valid_challenge(),
            timeout: Some(60000),
            rp_id: "example.com".to_string(),
            allow_credentials: vec![ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: valid_credential_id(),
                transports: Some(vec!["usb".to_string(), "nfc".to_string(), "ble".to_string()]),
            }],
            user_verification: Some("preferred".to_string()),
            extensions: Some(json!({})),
        }
    }

    /// Error response for missing challenge
    pub fn missing_challenge_error_response() -> ServerResponse {
        ServerResponse {
            status: "failed".to_string(),
            error_message: "Missing challenge field!".to_string(),
        }
    }

    /// Error response for invalid signature
    pub fn invalid_signature_error_response() -> ServerResponse {
        ServerResponse {
            status: "failed".to_string(),
            error_message: "Can not validate response signature!".to_string(),
        }
    }

    /// Error response for user not found
    pub fn user_not_found_error_response() -> ServerResponse {
        ServerResponse {
            status: "failed".to_string(),
            error_message: "User does not exists!".to_string(),
        }
    }
}

/// Security test vectors
pub mod security {
    use super::*;

    /// Replay attack scenario - reusing old challenge
    pub fn replay_attack_attestation() -> ServerAuthenticatorAttestationResponse {
        // Use a known old challenge
        let client_data = json!({
            "challenge": "old_reused_challenge_123",
            "origin": "https://example.com",
            "type": "webauthn.create",
            "clientExtensions": {}
        });
        ServerAuthenticatorAttestationResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            attestation_object: valid_attestation_object(),
        }
    }

    /// Tampered client data JSON
    pub fn tampered_client_data_attestation() -> ServerAuthenticatorAttestationResponse {
        // Valid client data but signature doesn't match
        let client_data = json!({
            "challenge": valid_challenge(),
            "origin": "https://example.com",
            "type": "webauthn.create",
            "clientExtensions": {},
            "tampered": "true" // Extra field that would break signature
        });
        ServerAuthenticatorAttestationResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            attestation_object: valid_attestation_object(),
        }
    }

    /// Credential hijacking attempt - wrong user handle
    pub fn credential_hijacking_assertion() -> ServerAuthenticatorAssertionResponse {
        ServerAuthenticatorAssertionResponse {
            authenticator_data: valid_authenticator_data(),
            client_data_json: valid_client_data_json_get(),
            signature: valid_signature(),
            user_handle: URL_SAFE_NO_PAD.encode("wrong_user_handle"), // Wrong user
        }
    }

    /// Cross-origin attempt
    pub fn cross_origin_attestation() -> ServerAuthenticatorAttestationResponse {
        let client_data = json!({
            "challenge": valid_challenge(),
            "origin": "https://malicious-site.com", // Different origin
            "type": "webauthn.create",
            "clientExtensions": {}
        });
        ServerAuthenticatorAttestationResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
            attestation_object: valid_attestation_object(),
        }
    }
}