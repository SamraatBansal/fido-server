use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::*;

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(User))]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(User))]
#[diesel(table_name = registration_challenges)]
pub struct RegistrationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = registration_challenges)]
pub struct NewRegistrationChallenge {
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(User))]
#[diesel(table_name = authentication_challenges)]
pub struct AuthenticationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = authentication_challenges)]
pub struct NewAuthenticationChallenge {
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub state_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}