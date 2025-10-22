//! Data Transfer Objects (DTOs) for FIDO2/WebAuthn API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
#[derive(Debug, Serialize, Deserialize)]
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

/// Request for attestation options (credential creation)
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

/// Response for attestation options
#[derive(Debug, Serialize)]
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

/// Request for assertion options (credential get)
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub user_verification: Option<String>,
}

/// Response for assertion options
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u64>,
    pub rp_id: String,
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Server public key credential (for attestation/result and assertion/result)
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(default)]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Server authenticator response (union type)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Server authenticator attestation response
#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Server authenticator assertion response
#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
    pub client_data_json: String,
}

/// Server public key credential user entity
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Server public key credential descriptor
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Public key credential RP entity
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: Option<String>,
}

/// Public key credential parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i64,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub require_resident_key: Option<bool>,
    pub user_verification: Option<String>,
    pub authenticator_attachment: Option<String>,
}