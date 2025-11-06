//! Common DTO types

use serde::{Deserialize, Serialize};
use webauthn_rs_proto::AuthenticatorTransport;

/// Standard server response format
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    pub fn failed(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

/// Server public key credential user entity (base64url encoded ID)
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String, // base64url encoded
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Server public key credential descriptor (base64url encoded ID)
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String, // base64url encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// Server authenticator response (base trait)
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
}

/// Server authenticator attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
    #[serde(rename = "attestationObject")]
    pub attestation_object: String, // base64url encoded
}

/// Server authenticator assertion response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String, // base64url encoded
    pub signature: String, // base64url encoded
    #[serde(rename = "userHandle")]
    pub user_handle: String, // base64url encoded (can be empty)
}

/// Server public key credential (base64url encoded ID)
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String, // base64url encoded
    #[serde(rename = "type")]
    pub credential_type: String,
    pub response: ServerCredentialResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerCredentialResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}