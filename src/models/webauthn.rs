//! WebAuthn domain models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, email: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            email,
            display_name,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Credential model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: u64,
    pub transports: Vec<String>,
    pub attestation_type: String,
    pub aaguid: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Credential {
    pub fn new(
        user_id: String,
        credential_id: String,
        public_key: String,
        transports: Vec<String>,
        attestation_type: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            credential_id,
            public_key,
            sign_count: 0,
            transports,
            attestation_type,
            aaguid: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Challenge model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub user_id: Option<String>,
    pub value: String,
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl Challenge {
    pub fn new_registration(user_id: String, value: String, expires_in_seconds: u64) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: Some(user_id),
            value,
            challenge_type: ChallengeType::Registration,
            expires_at: now + chrono::Duration::seconds(expires_in_seconds as i64),
            created_at: now,
            consumed: false,
        }
    }
    
    pub fn new_authentication(value: String, expires_in_seconds: u64) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: None,
            value,
            challenge_type: ChallengeType::Authentication,
            expires_at: now + chrono::Duration::seconds(expires_in_seconds as i64),
            created_at: now,
            consumed: false,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}