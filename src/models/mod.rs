use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub attestation_format: String,
    pub attestation_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct Challenge {
    pub id: String,
    pub user_id: Option<String>,
    pub challenge: String,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: String,
    pub used: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub id: String,
    pub user_id: Option<String>,
    pub challenge: String,
    pub challenge_type: String,
    pub expires_at: String,
}