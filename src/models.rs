use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserMapping {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub external_id: String,
    pub external_type: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub user_id: Uuid,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub user_id: Option<Uuid>,
    pub credential_id: Option<Vec<u8>>,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct StartRegistrationRequest {
    #[validate(length(min = 1, max = 64))]
    pub username: String,
    #[validate(length(min = 1, max = 128))]
    pub display_name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct FinishRegistrationRequest {
    pub credential_creation_response: PublicKeyCredentialCreationResponse,
    pub user_id: Uuid,
    pub challenge: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct StartAuthenticationRequest {
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct FinishAuthenticationRequest {
    pub credential_request_response: PublicKeyCredentialRequestResponse,
    pub challenge: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RevokeCredentialRequest {
    pub credential_id: String,
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateCredentialRequest {
    pub credential_id: String,
    pub user_id: Uuid,
    pub new_display_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateMappingRequest {
    pub user_id: Uuid,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug, Serialize)]
pub struct MappingResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl From<Credential> for CredentialResponse {
    fn from(credential: Credential) -> Self {
        CredentialResponse {
            id: base64::encode_config(&credential.credential_id, base64::URL_SAFE_NO_PAD),
            user_id: credential.user_id,
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            is_active: credential.is_active,
            transports: credential
                .transports
                .as_ref()
                .and_then(|t| serde_json::from_str::<Vec<String>>(t).ok()),
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
        }
    }
}

impl From<UserMapping> for MappingResponse {
    fn from(mapping: UserMapping) -> Self {
        MappingResponse {
            id: mapping.id,
            user_id: mapping.user_id,
            credential_id: base64::encode_config(&mapping.credential_id, base64::URL_SAFE_NO_PAD),
            external_id: mapping.external_id,
            external_type: mapping.external_type,
            metadata: mapping.metadata,
            created_at: mapping.created_at,
        }
    }
}