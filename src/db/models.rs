//! Database models

use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// User model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Credential model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub user_verification: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: String,
    pub transports: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Challenge model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: uuid::Uuid,
    pub challenge_id: Vec<u8>,
    pub user_id: Option<uuid::Uuid>,
    pub challenge_type: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// New user for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

/// New credential for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: uuid::Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub user_verification: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: String,
    pub transports: Vec<String>,
}

/// New challenge for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge_id: Vec<u8>,
    pub user_id: Option<uuid::Uuid>,
    pub challenge_type: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}