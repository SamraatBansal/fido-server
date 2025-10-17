//! WebAuthn data models for FIDO2 conformance

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

/// Registration request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

/// Registration response structure
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
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Authentication request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub user_verification: Option<String>,
}

/// Authentication response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u32>,
    pub rp_id: String,
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub user_verification: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// RP entity structure
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
    pub type_field: String,
    pub alg: i32,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_field: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub require_resident_key: Option<bool>,
    pub authenticator_attachment: Option<String>,
    pub user_verification: Option<String>,
}

/// Server public key credential (for attestation/result and assertion/result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "type")]
    pub type_field: String,
}

/// Authenticator response (union type)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Assertion response
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