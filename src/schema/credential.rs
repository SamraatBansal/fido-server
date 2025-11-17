use crate::schema::credentials;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(super::user::User, foreign_key = user_id))]
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