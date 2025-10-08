//! Database models

use serde::{Deserialize, Serialize};

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
}

/// Credential model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub created_at: String,
}

/// Challenge model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub challenge_id: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: String,
}