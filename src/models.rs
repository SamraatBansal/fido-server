//! FIDO2/WebAuthn request and response models

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }
}

/// Registration request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub require_resident_key: Option<bool>,
    pub authenticator_attachment: Option<String>,
    pub user_verification: Option<String>,
}

/// Registration response options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Relying Party entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Server public key credential (for attestation result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Authentication request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Authentication response options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Server public key credential (for assertion result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialAssertion {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}