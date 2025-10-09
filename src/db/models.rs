//! Database models

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Credential model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub attestation_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Challenge model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub challenge_data: String,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed: bool,
}