// @generated automatically by Diesel CLI.

diesel::table! {
    authentication_challenges (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        challenge -> Bytea,
        state_data -> Bytea,
        expires_at -> Timestamp,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        sign_count -> Int8,
        backup_eligible -> Bool,
        backup_state -> Bool,
        attestation_format -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        last_used_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    registration_challenges (id) {
        id -> Uuid,
        user_id -> Uuid,
        challenge -> Bytea,
        state_data -> Bytea,
        expires_at -> Timestamp,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        user_handle -> Bytea,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::joinable!(authentication_challenges -> users (user_id));
diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(registration_challenges -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    authentication_challenges,
    credentials,
    registration_challenges,
    users,
);

// Model definitions

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
}

impl NewUser {
    pub fn new(username: String, display_name: String) -> Self {
        let user_handle = uuid::Uuid::new_v4().as_bytes().to_vec();
        Self {
            username,
            display_name,
            user_handle,
        }
    }
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: Option<String>,
}

#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i64>,
    pub last_used_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = registration_challenges)]
pub struct RegistrationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = registration_challenges)]
pub struct NewRegistrationChallenge {
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = authentication_challenges)]
pub struct AuthenticationChallenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = authentication_challenges)]
pub struct NewAuthenticationChallenge {
    pub user_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: NaiveDateTime,
}