use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

// FIDO Conformance API Request/Response Types

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<serde_json::Value>,
    #[serde(default)]
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: serde_json::Value,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", default)]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String, // base64url encoded
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String, // base64url encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<webauthn_rs::prelude::AuthenticatorTransport>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<webauthn_rs::prelude::UserVerificationPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", default)]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<webauthn_rs::prelude::UserVerificationPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerPublicKeyCredential {
    pub id: String, // base64url encoded
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults", default)]
    pub get_client_extension_results: serde_json::Value,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String, // base64url encoded
    pub attestation_object: String, // base64url encoded
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String, // base64url encoded
    pub client_data_json: String, // base64url encoded
    pub signature: String, // base64url encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>, // base64url encoded
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }
    
    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

// Internal storage models
#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>, // WebAuthn user ID
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct StoredChallenge {
    pub id: String,
    pub user_id: Uuid,
    pub challenge_type: ChallengeType,
    pub challenge_data: String, // JSON serialized challenge state
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ChallengeType {
    Registration,
    Authentication,
}