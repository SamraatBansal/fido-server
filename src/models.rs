use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Queryable, Identifiable, Associations, Serialize, Deserialize, Clone)]
#[diesel(belongs_to(User))]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<String>,
}

#[derive(Queryable, Identifiable, Associations)]
#[diesel(belongs_to(User))]
#[diesel(table_name = crate::schema::challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub challenge_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub challenge_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}