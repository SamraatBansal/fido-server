//! Database models and schema for the FIDO Server

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    #[diesel(deserialize_as = Vec<u8>)]
    pub credential_id: Vec<u8>,
    #[diesel(deserialize_as = Vec<u8>)]
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_format: String,
    #[diesel(deserialize_as = Option<Vec<u8>>)]
    pub aaguid: Option<Vec<u8>>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: String,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: chrono::NaiveDateTime,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub user_id: Option<Uuid>,
    pub challenge: String,
    pub challenge_type: String,
    pub expires_at: chrono::NaiveDateTime,
}