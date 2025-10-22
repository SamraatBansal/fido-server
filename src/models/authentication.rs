//! Authentication-related models for FIDO2/WebAuthn

use serde::{Deserialize, Serialize};
use super::{
    ServerPublicKeyCredential, ServerResponse, ServerPublicKeyCredentialDescriptor,
};

/// Request for authentication challenge options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Response for authentication challenge options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

impl ServerPublicKeyCredentialGetOptionsResponse {
    pub fn success(challenge: String, rp_id: String) -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: Some(60000),
            rp_id,
            allow_credentials: vec![],
            user_verification: Some("preferred".to_string()),
            extensions: None,
        }
    }
}

/// Server authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Authentication completion request
pub type AuthenticationCompletionRequest = ServerPublicKeyCredential;

/// Authentication completion response
pub type AuthenticationCompletionResponse = ServerResponse;