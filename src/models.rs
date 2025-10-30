//! WebAuthn data models and request/response structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::proto::{
    AttestationConveyancePreference, AuthenticatorAttachment, AuthenticatorSelectionCriteria,
    AuthenticatorTransport, COSEAlgorithm, COSEKey, PublicKeyCredentialParameters,
    UserVerificationPolicy,
};

/// Standard server response format
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

/// Request for registration options
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

/// Response for registration options
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u32>,
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: AttestationConveyancePreference,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Relying Party entity
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// User entity for registration
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Credential descriptor
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// Server public key credential (base64url encoded)
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Authenticator response (base for both attestation and assertion)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Attestation response
#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Assertion response
#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Request for authentication options
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
}

/// Response for authentication options
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
    pub challenge: String,
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Registration result response
#[derive(Debug, Serialize)]
pub struct RegistrationResultResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
    pub credential_id: Option<String>,
}

/// Authentication result response
#[derive(Debug, Serialize)]
pub struct AuthenticationResultResponse {
    #[serde(flatten)]
    pub response: ServerResponse,
}

/// Challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

/// Stored challenge information
#[derive(Debug, Clone)]
pub struct StoredChallenge {
    pub challenge: String,
    pub user_id: Uuid,
    pub challenge_type: ChallengeType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// User model
#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Credential model
#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: COSEKey,
    pub sign_count: u32,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl User {
    /// Convert to webauthn-rs User
    pub fn to_webauthn_user(&self) -> webauthn_rs::proto::User {
        webauthn_rs::proto::User {
            id: self.id.as_bytes().to_vec(),
            name: self.username.clone(),
            display_name: self.display_name.clone(),
        }
    }
}

impl Credential {
    /// Convert to webauthn-rs Credential
    pub fn to_webauthn_credential(&self) -> webauthn_rs::proto::Credential {
        webauthn_rs::proto::Credential {
            credential_id: self.credential_id.clone(),
            public_key: self.public_key.clone(),
            sign_count: self.sign_count,
            attestation_format: self.attestation_format.clone(),
            attestation_data: self.attestation_data.clone(),
        }
    }
}