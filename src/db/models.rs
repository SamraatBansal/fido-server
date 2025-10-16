//! Database models for FIDO2/WebAuthn

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// User model
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New user for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
}

/// WebAuthn credential model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
    pub transports: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
    pub transports: Option<String>,
}

/// Challenge model for storing registration/authentication challenges
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: String,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub user_id: Option<Uuid>,
    pub challenge: String,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, display_name: String, email: Option<String>) -> NewUser {
        NewUser {
            username,
            display_name,
            email,
        }
    }
}

impl Credential {
    pub fn new(
        user_id: Uuid,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        sign_count: i64,
        attestation_format: String,
        attestation_data: Option<Vec<u8>>,
        transports: Option<String>,
    ) -> NewCredential {
        NewCredential {
            user_id,
            credential_id,
            public_key,
            sign_count,
            attestation_format,
            attestation_data,
            transports,
        }
    }
}

impl Challenge {
    pub fn new(
        user_id: Option<Uuid>,
        challenge: String,
        challenge_type: String,
        expires_at: DateTime<Utc>,
    ) -> NewChallenge {
        NewChallenge {
            user_id,
            challenge,
            challenge_type,
            expires_at,
        }
    }
}