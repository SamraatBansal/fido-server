//! Database models

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema_db::{users, credentials, challenge_states};

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Insertable, Serialize, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>,
}

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = credentials, primary_key(id))]
pub struct Credential {
    pub id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub credential_type: String,
    pub transports: Option<Vec<Option<String>>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: Option<String>,
    pub attestation_trust_path: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Insertable, Serialize, Deserialize, Debug)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub credential_type: String,
    pub transports: Option<Vec<Option<String>>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: Option<String>,
    pub attestation_trust_path: Option<serde_json::Value>,
}

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = challenge_states)]
pub struct ChallengeState {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub operation: String,
    pub state_data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Insertable, Serialize, Deserialize, Debug)]
#[diesel(table_name = challenge_states)]
pub struct NewChallengeState {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub operation: String,
    pub state_data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
}