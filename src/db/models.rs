//! Database models using Diesel

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use webauthn_rs::proto::COSEKey;

use crate::schema::{users, credentials, challenges};

/// User table model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New user for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

/// Update user
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Credential table model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: serde_json::Value, // COSEKey serialized as JSON
    pub sign_count: i32,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: serde_json::Value,
    pub sign_count: i32,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
}

/// Update credential
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i32>,
    pub updated_at: DateTime<Utc>,
}

/// Challenge table model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Uuid,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Uuid,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

impl From<crate::models::User> for User {
    fn from(user: crate::models::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl From<User> for crate::models::User {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl TryFrom<crate::models::Credential> for Credential {
    type Error = serde_json::Error;

    fn try_from(credential: crate::models::Credential) -> Result<Self, Self::Error> {
        Ok(Self {
            id: credential.id,
            credential_id: credential.credential_id,
            user_id: credential.user_id,
            public_key: serde_json::to_value(&credential.public_key)?,
            sign_count: credential.sign_count as i32,
            attestation_format: credential.attestation_format,
            attestation_data: credential.attestation_data,
            created_at: credential.created_at,
            updated_at: credential.updated_at,
        })
    }
}

impl TryFrom<Credential> for crate::models::Credential {
    type Error = serde_json::Error;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        let public_key: COSEKey = serde_json::from_value(credential.public_key)?;
        Ok(Self {
            id: credential.id,
            credential_id: credential.credential_id,
            user_id: credential.user_id,
            public_key,
            sign_count: credential.sign_count as u32,
            attestation_format: credential.attestation_format,
            attestation_data: credential.attestation_data,
            created_at: credential.created_at,
            updated_at: credential.updated_at,
        })
    }
}

impl From<crate::models::StoredChallenge> for NewChallenge {
    fn from(challenge: crate::models::StoredChallenge) -> Self {
        Self {
            id: Uuid::new_v4(),
            challenge: challenge.challenge,
            user_id: challenge.user_id,
            challenge_type: match challenge.challenge_type {
                crate::models::ChallengeType::Registration => "registration".to_string(),
                crate::models::ChallengeType::Authentication => "authentication".to_string(),
            },
            expires_at: challenge.expires_at,
        }
    }
}

impl TryFrom<Challenge> for crate::models::StoredChallenge {
    type Error = crate::error::AppError;

    fn try_from(challenge: Challenge) -> Result<Self, Self::Error> {
        let challenge_type = match challenge.challenge_type.as_str() {
            "registration" => crate::models::ChallengeType::Registration,
            "authentication" => crate::models::ChallengeType::Authentication,
            _ => return Err(crate::error::AppError::InvalidInput("Invalid challenge type".to_string())),
        };

        Ok(Self {
            challenge: challenge.challenge,
            user_id: challenge.user_id,
            challenge_type,
            expires_at: challenge.expires_at,
        })
    }
}