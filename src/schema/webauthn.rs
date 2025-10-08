//! WebAuthn FIDO2 conformance API schemas

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Registration options request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegistrationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    pub authenticator_selection: Option<serde_json::Value>,
    pub attestation: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

/// Registration options response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: serde_json::Value,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<serde_json::Value>,
    pub timeout: u64,
    pub exclude_credentials: Vec<serde_json::Value>,
    pub authenticator_selection: Option<serde_json::Value>,
    pub attestation: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

/// Server public key credential user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Authentication options request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    pub user_verification: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

/// Authentication options response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: u64,
    pub rp_id: String,
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: String,
    pub extensions: Option<serde_json::Value>,
}

/// Server public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Vec<String>,
}

/// Server response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

/// Re-export webauthn-rs types
pub use webauthn_rs::prelude::*;