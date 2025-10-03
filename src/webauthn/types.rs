use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub credentials: Vec<Passkey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub device_type: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMapping {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String, // "email", "account_id", etc.
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub user_id: Uuid,
    pub challenge_data: CreationChallengeResponse,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub user_id: Option<Uuid>,
    pub credential_id: Option<String>,
    pub challenge_data: RequestChallengeResponse,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    pub username: String,
    pub credential_creation_response: PublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: Option<String>,
    pub credential_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub assertion_response: PublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMappingRequest {
    pub user_id: Uuid,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}