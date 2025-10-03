use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
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
    pub challenge_data: RegistrationChallengeResponse,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub user_id: Option<Uuid>,
    pub credential_id: Option<Vec<u8>>,
    pub challenge: String,
    pub challenge_data: AuthenticationChallengeResponse,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: Option<UserVerificationPolicy>,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub resident_key: Option<ResidentKeyRequirement>,
    pub extensions: Option<RequestRegistrationExtensions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    pub username: String,
    pub registration_response: RegistrationResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: Option<String>,
    pub user_verification: Option<UserVerificationPolicy>,
    pub user_presence: Option<UserPresencePolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub authentication_response: AuthenticationResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub id: Uuid,
    pub credential_id: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeCredentialRequest {
    pub credential_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateCredentialRequest {
    pub credential_id: String,
    pub new_display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMappingRequest {
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MappingResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}