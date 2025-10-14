//! Test fixtures and data factories for FIDO2/WebAuthn testing

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Valid base64url challenge (16 bytes)
pub fn valid_challenge() -> String {
    URL_SAFE_NO_PAD.encode(b"valid_challenge_16b")
}

/// Expired challenge (for testing expiration)
pub fn expired_challenge() -> String {
    URL_SAFE_NO_PAD.encode(b"expired_challenge_16b")
}

/// Invalid base64url string
pub fn invalid_base64url() -> String {
    "invalid!base64url@string".to_string()
}

/// Valid user ID (base64url encoded)
pub fn valid_user_id() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

/// Valid credential ID (base64url encoded)
pub fn valid_credential_id() -> String {
    URL_SAFE_NO_PAD.encode(&[0x4F, 0x9B, 0x5A, 0x7C, 0x2E, 0x8D, 0x3F, 0xA1])
}

/// Valid client data JSON (base64url encoded)
pub fn valid_client_data_json_create() -> String {
    let client_data = serde_json::json!({
        "challenge": valid_challenge(),
        "origin": "https://example.com",
        "type": "webauthn.create",
        "clientExtensions": {}
    });
    URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes())
}

/// Valid client data JSON for get (base64url encoded)
pub fn valid_client_data_json_get() -> String {
    let client_data = serde_json::json!({
        "challenge": valid_challenge(),
        "origin": "https://example.com",
        "type": "webauthn.get",
        "clientExtensions": {}
    });
    URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes())
}

/// Valid attestation object (base64url encoded)
pub fn valid_attestation_object() -> String {
    // This is a mock attestation object - in real tests, use actual CBOR data
    let attestation = vec![
        0xA3, 0x67, 0x66, 0x6D, 0x74, 0x01, 0x68, 0x61, 0x74, 0x74, 0x53, 0x74,
        0x6D, 0x74, 0x58, 0x47, 0xD8, 0x60, 0x18, 0x6C, 0x06, 0x2A, 0x86, 0x48,
        0xCE, 0x3D, 0x04, 0x01, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x04, 0x03,
        0x03, 0x41, 0x00, 0x04, 0x42, 0x9A, 0x3A, 0x7B, 0x3C, 0x5D, 0x6E, 0x2F,
        0x8A, 0x3F, 0x9B, 0x21, 0x4E, 0x1A, 0xC7, 0x59, 0x30, 0x8A, 0x6B, 0x0C,
        0x85, 0x72, 0x95, 0x6A, 0x93, 0x56, 0x9E, 0x3B, 0x5B, 0x88, 0xBD, 0x2A,
        0xC6, 0x81, 0x9A, 0x48, 0x5E, 0x4B, 0x2C, 0x8D, 0x19, 0x4C, 0x6B, 0x34,
        0x58, 0x19, 0x7C, 0x8A, 0x9A, 0x3C, 0x1F, 0xA1, 0x67, 0x61, 0x75, 0x74,
        0x68, 0x44, 0x61, 0x74, 0x61, 0x58, 0x4C, 0x49, 0x96, 0x0D, 0xE5, 0x90,
        0x38, 0x6F, 0x84, 0x31, 0x95, 0xCF, 0x6D, 0xD5, 0x8C, 0xA4, 0x20, 0xAA,
        0x06, 0x63, 0x8A, 0x62, 0x2F, 0x45, 0x61, 0x2E, 0xC8, 0x15, 0x5A, 0x08,
        0x10, 0x3A, 0x25, 0x82, 0x5A, 0xB2, 0x72, 0x65, 0x6D, 0x61, 0x69, 0x6E,
        0x69, 0x6E, 0x66, 0x6F, 0x67, 0x61, 0x6D, 0x65, 0x6E, 0x61, 0x6D, 0x65,
        0x6B, 0x65, 0x79, 0x69, 0x64, 0x58, 0x20, 0x4F, 0x9B, 0x5A, 0x7C, 0x2E,
        0x8D, 0x3F, 0xA1, 0x42, 0x9A, 0x3A, 0x7B, 0x3C, 0x5D, 0x6E, 0x2F, 0x8A,
        0x3F, 0x9B, 0x21, 0x4E, 0x1A, 0xC7, 0x59, 0x30, 0x8A, 0x6B, 0x0C
    ];
    URL_SAFE_NO_PAD.encode(attestation)
}

/// Valid authenticator data (base64url encoded)
pub fn valid_authenticator_data() -> String {
    let auth_data = vec![
        0x49, 0x96, 0x0D, 0xE5, 0x90, 0x38, 0x6F, 0x84, 0x31, 0x95, 0xCF, 0x6D,
        0xD5, 0x8C, 0xA4, 0x20, 0xAA, 0x06, 0x63, 0x8A, 0x62, 0x2F, 0x45, 0x61,
        0x2E, 0xC8, 0x15, 0x5A, 0x08, 0x10, 0x3A, 0x25, 0x82, 0x5A, 0xB2, 0x01,
        0x00, 0x00, 0x00
    ];
    URL_SAFE_NO_PAD.encode(auth_data)
}

/// Valid signature (base64url encoded)
pub fn valid_signature() -> String {
    let signature = vec![
        0x30, 0x45, 0x02, 0x20, 0x42, 0x9A, 0x3A, 0x7B, 0x3C, 0x5D, 0x6E, 0x2F,
        0x8A, 0x3F, 0x9B, 0x21, 0x4E, 0x1A, 0xC7, 0x59, 0x30, 0x8A, 0x6B, 0x0C,
        0x85, 0x72, 0x95, 0x6A, 0x93, 0x56, 0x9E, 0x3B, 0x5B, 0x88, 0xBD, 0x2A,
        0xC6, 0x81, 0x9A, 0x48, 0x5E, 0x4B, 0x02, 0x21, 0x00, 0x8A, 0x9A, 0x3C,
        0x1F, 0xA1, 0x67, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x58,
        0x4C, 0x49, 0x96, 0x0D, 0xE5, 0x90, 0x38, 0x6F, 0x84, 0x31, 0x95, 0xCF
    ];
    URL_SAFE_NO_PAD.encode(signature)
}

/// Valid user handle (base64url encoded)
pub fn valid_user_handle() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

/// Empty user handle (for testing)
pub fn empty_user_handle() -> String {
    URL_SAFE_NO_PAD.encode("")
}

/// Request structures for testing

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub require_resident_key: Option<bool>,
    pub authenticator_attachment: Option<String>,
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u32>,
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub raw_id: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub get_client_extension_results: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u32>,
    pub rp_id: String,
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAssertionPublicKeyCredential {
    pub id: String,
    pub raw_id: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub get_client_extension_results: Option<serde_json::Value>,
}

/// Factory functions for creating test requests

pub fn create_valid_attestation_options_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "alice@example.com".to_string(),
        display_name: "Alice Smith".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
        }),
        attestation: Some("direct".to_string()),
    }
}

pub fn create_valid_attestation_result_request() -> ServerPublicKeyCredential {
    ServerPublicKeyCredential {
        id: valid_credential_id(),
        raw_id: valid_credential_id(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: valid_client_data_json_create(),
            attestation_object: valid_attestation_object(),
        },
        cred_type: "public-key".to_string(),
        get_client_extension_results: Some(serde_json::json!({})),
    }
}

pub fn create_valid_assertion_options_request() -> ServerPublicKeyCredentialGetOptionsRequest {
    ServerPublicKeyCredentialGetOptionsRequest {
        username: "alice@example.com".to_string(),
        user_verification: Some("preferred".to_string()),
    }
}

pub fn create_valid_assertion_result_request() -> ServerAssertionPublicKeyCredential {
    ServerAssertionPublicKeyCredential {
        id: valid_credential_id(),
        raw_id: valid_credential_id(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: valid_authenticator_data(),
            client_data_json: valid_client_data_json_get(),
            signature: valid_signature(),
            user_handle: valid_user_handle(),
        },
        cred_type: "public-key".to_string(),
        get_client_extension_results: Some(serde_json::json!({})),
    }
}