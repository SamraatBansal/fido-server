//! Database models

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::*;

/// User model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
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
#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

/// Credential model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_data: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New credential for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_data: Option<Vec<u8>>,
}

/// User mapping model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = user_mappings)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserMapping {
    pub id: Uuid,
    pub external_id: String,
    pub credential_id: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New user mapping for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = user_mappings)]
pub struct NewUserMapping {
    pub id: Uuid,
    pub external_id: String,
    pub credential_id: String,
    pub user_id: Uuid,
}

/// Challenge model
#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// New challenge for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}