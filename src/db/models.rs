//! Database models using Diesel ORM

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::db::schema::*;

/// User model
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
    pub username: String,
    pub display_name: String,
}

/// Credential model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize, Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub attestation_type: Option<String>,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub attestation_type: Option<String>,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<serde_json::Value>,
}

/// Challenge model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: String,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge: String,
    pub username: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}