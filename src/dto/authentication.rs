//! Authentication DTO types for FIDO2/WebAuthn compliance

use serde::{Deserialize, Serialize};
use webauthn_rs_proto::UserVerificationPolicy;
use super::common::*;

/// Server public key credential get options request  
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Server public key credential get options response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub server_response: ServerResponse,
    pub challenge: String, // base64url encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Authentication result request (from client)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationResultRequest {
    #[serde(flatten)]
    pub credential: ServerPublicKeyCredential,
}

/// Authentication result response (to client)
pub type AuthenticationResultResponse = ServerResponse;