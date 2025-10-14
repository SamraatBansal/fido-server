//! Data models for FIDO2/WebAuthn

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Server response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse<T> {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorMessage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub data: Option<T>,
}

impl<T> ServerResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "ok".to_string(),
            errorMessage: None,
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> ServerResponse<()> {
        ServerResponse {
            status: "failed".to_string(),
            errorMessage: Some(message.into()),
            data: None,
        }
    }
}

/// Registration request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub displayName: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Registration response options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorMessage: Option<String>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub excludeCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

/// Authentication response options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorMessage: Option<String>,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub rpId: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

/// Public key credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub rawId: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub getClientExtensionResults: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
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
    pub clientDataJSON: String,
    pub attestationObject: String,
}

/// Assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub clientDataJSON: String,
    pub authenticatorData: String,
    pub signature: String,
    pub userHandle: Option<String>,
}

/// RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: String,
}

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub displayName: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub alg_type: String,
    pub alg: i32,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requireResidentKey: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorAttachment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: serde_json::Value,
}

/// User model for database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Credential model for database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_type: String,
    pub aaguid: Option<Uuid>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Challenge model for database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}