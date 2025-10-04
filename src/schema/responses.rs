//! Response DTOs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

impl From<crate::db::models::User> for UserEntity {
    fn from(user: crate::db::models::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    pub challenge: String,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationFinishResponse {
    pub credential_id: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationStartResponse {
    pub challenge: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub user_verification: Option<UserVerificationPolicy>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationFinishResponse {
    pub user_id: String,
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub id: Uuid,
    pub credential_id: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

impl From<crate::db::models::Credential> for CredentialInfo {
    fn from(credential: crate::db::models::Credential) -> Self {
        Self {
            id: credential.id,
            credential_id: base64::encode(&credential.credential_id),
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsListResponse {
    pub credentials: Vec<CredentialInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl ErrorResponse {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            timestamp: Utc::now(),
        }
    }
}