use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>, // WebAuthn user.id
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>, // WebAuthn credential ID
    pub public_key: Vec<u8>,    // COSE public key
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: Option<String>,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub status: String,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub challenge_data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ActiveCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: Option<String>,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub status: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: Option<String>,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewChallenge {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub challenge_data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
}