//! Database models using simplified in-memory storage

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

/// Credential model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Challenge model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub challenge: String,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}