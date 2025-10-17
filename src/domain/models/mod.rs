//! Domain models for FIDO2/WebAuthn

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

/// Request for attestation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

/// Response for attestation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Request for assertion options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Response for assertion options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Server public key credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub r#type: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Server authenticator response (enum for attestation/assertion)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Server authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Server authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Server public key credential user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Server public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    pub r#type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Public key credential RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    pub r#type: String,
    pub alg: i64,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}