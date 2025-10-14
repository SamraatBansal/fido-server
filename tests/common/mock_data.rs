//! Mock data generators for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Valid attestation options request
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub displayName: String,
    pub attestation: Option<String>,
    pub authenticatorSelection: Option<AuthenticatorSelection>,
}

/// Valid attestation options response
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationOptionsResponse {
    pub status: String,
    pub errorMessage: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    pub timeout: u64,
    pub excludeCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub authenticatorSelection: AuthenticatorSelection,
    pub attestation: String,
}

/// Valid assertion options request
#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: String,
    pub userVerification: Option<String>,
}

/// Valid assertion options response
#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionOptionsResponse {
    pub status: String,
    pub errorMessage: String,
    pub challenge: String,
    pub timeout: u64,
    pub rpId: String,
    pub allowCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub userVerification: String,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub requireResidentKey: bool,
    pub authenticatorAttachment: String,
    pub userVerification: String,
}

/// RP entity
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: String,
}

/// User entity
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub displayName: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Credential descriptor
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Server public key credential
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
}

/// Authenticator response (base for attestation and assertion)
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Assertion response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
}

impl MockDataFactory {
    /// Create a valid attestation options request
    pub fn valid_attestation_options_request() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: "alice@example.com".to_string(),
            displayName: "Alice Smith".to_string(),
            attestation: Some("direct".to_string()),
            authenticatorSelection: Some(AuthenticatorSelection {
                requireResidentKey: false,
                authenticatorAttachment: "platform".to_string(),
                userVerification: "preferred".to_string(),
            }),
        }
    }

    /// Create a valid assertion options request
    pub fn valid_assertion_options_request() -> AssertionOptionsRequest {
        AssertionOptionsRequest {
            username: "alice@example.com".to_string(),
            userVerification: Some("preferred".to_string()),
        }
    }

    /// Create a valid attestation options response
    pub fn valid_attestation_options_response() -> AttestationOptionsResponse {
        AttestationOptionsResponse {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: "Example RP".to_string(),
                id: "example.com".to_string(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: BASE64.encode("alice_user_id".as_bytes()),
                name: "alice".to_string(),
                displayName: "Alice Smith".to_string(),
            },
            challenge: generate_random_challenge(),
            pubKeyCredParams: vec![PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            }],
            timeout: 60000,
            excludeCredentials: vec![],
            authenticatorSelection: AuthenticatorSelection {
                requireResidentKey: false,
                authenticatorAttachment: "platform".to_string(),
                userVerification: "preferred".to_string(),
            },
            attestation: "direct".to_string(),
        }
    }

    /// Create a valid assertion options response
    pub fn valid_assertion_options_response() -> AssertionOptionsResponse {
        AssertionOptionsResponse {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
            challenge: generate_random_challenge(),
            timeout: 60000,
            rpId: "example.com".to_string(),
            allowCredentials: vec![ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: BASE64.encode("test_credential_id".as_bytes()),
                transports: Some(vec!["internal".to_string(), "usb".to_string()]),
            }],
            userVerification: "preferred".to_string(),
        }
    }

    /// Create a valid attestation result request
    pub fn valid_attestation_result_request() -> ServerPublicKeyCredential {
        ServerPublicKeyCredential {
            id: BASE64.encode("test_credential_id".as_bytes()),
            raw_id: BASE64.encode("test_credential_id".as_bytes()),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorResponse {
                client_data_json: BASE64.encode(r#"{"type":"webauthn.create","challenge":"test_challenge","origin":"https://example.com"}"#.as_bytes()),
            },
            get_client_extension_results: Some(serde_json::json!({})),
        }
    }

    /// Create a valid assertion result request
    pub fn valid_assertion_result_request() -> ServerPublicKeyCredential {
        ServerPublicKeyCredential {
            id: BASE64.encode("test_credential_id".as_bytes()),
            raw_id: BASE64.encode("test_credential_id".as_bytes()),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorResponse {
                client_data_json: BASE64.encode(r#"{"type":"webauthn.get","challenge":"test_challenge","origin":"https://example.com"}"#.as_bytes()),
            },
            get_client_extension_results: Some(serde_json::json!({})),
        }
    }

    /// Create invalid request data for negative testing
    pub fn invalid_attestation_options_requests() -> Vec<AttestationOptionsRequest> {
        vec![
            // Missing username
            AttestationOptionsRequest {
                username: "".to_string(),
                displayName: "Alice Smith".to_string(),
                attestation: Some("direct".to_string()),
                authenticatorSelection: None,
            },
            // Missing displayName
            AttestationOptionsRequest {
                username: "alice@example.com".to_string(),
                displayName: "".to_string(),
                attestation: Some("direct".to_string()),
                authenticatorSelection: None,
            },
            // Invalid attestation value
            AttestationOptionsRequest {
                username: "alice@example.com".to_string(),
                displayName: "Alice Smith".to_string(),
                attestation: Some("invalid".to_string()),
                authenticatorSelection: None,
            },
        ]
    }

    /// Create invalid assertion options requests
    pub fn invalid_assertion_options_requests() -> Vec<AssertionOptionsRequest> {
        vec![
            // Missing username
            AssertionOptionsRequest {
                username: "".to_string(),
                userVerification: Some("preferred".to_string()),
            },
            // Invalid userVerification
            AssertionOptionsRequest {
                username: "alice@example.com".to_string(),
                userVerification: Some("invalid".to_string()),
            },
        ]
    }
}

/// Factory for creating mock data
pub struct MockDataFactory;

/// Generate a random base64url challenge
pub fn generate_random_challenge() -> String {
    let challenge_bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)
}

/// Generate a random UUID as base64
pub fn generate_random_user_id() -> String {
    BASE64.encode(Uuid::new_v4().as_bytes())
}

/// Generate malformed base64 strings for testing
pub fn malformed_base64_strings() -> Vec<String> {
    vec![
        "!!!invalid!!!".to_string(),
        "invalid base64 @#$".to_string(),
        "aW52YWxpZCBiYXNlNjQ=".to_string(), // valid base64 but invalid base64url
        "".to_string(),
        "   ".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_data_creation() {
        let request = MockDataFactory::valid_attestation_options_request();
        assert_eq!(request.username, "alice@example.com");
        assert_eq!(request.displayName, "Alice Smith");
    }

    #[test]
    fn test_challenge_generation() {
        let challenge1 = generate_random_challenge();
        let challenge2 = generate_random_challenge();
        assert_ne!(challenge1, challenge2);
        assert!(!challenge1.is_empty());
    }
}