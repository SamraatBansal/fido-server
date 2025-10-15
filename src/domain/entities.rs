//! Domain entities for the FIDO2 server

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl User {
    pub fn new(username: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            display_name,
            created_at: now,
            updated_at: now,
            is_active: true,
        }
    }
}

/// Credential entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_backup_eligible: bool,
    pub is_resident_key: bool,
    pub user_verification_required: bool,
    pub transports: Vec<String>,
}

impl Credential {
    pub fn new(
        user_id: Uuid,
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        attestation_type: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            credential_public_key,
            attestation_type,
            aaguid: None,
            sign_count: 0,
            created_at: Utc::now(),
            last_used_at: None,
            is_backup_eligible: false,
            is_resident_key: false,
            user_verification_required: false,
            transports: Vec::new(),
        }
    }
}

/// Challenge entity for replay prevention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl Challenge {
    pub fn new(
        challenge: Vec<u8>,
        user_id: Option<Uuid>,
        challenge_type: ChallengeType,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            challenge,
            user_id,
            challenge_type,
            expires_at,
            created_at: Utc::now(),
            used_at: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}