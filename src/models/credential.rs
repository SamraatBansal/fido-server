use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: i64,
    pub aaguid: Option<Uuid>,
    pub credential_type: String,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: Option<bool>,
    pub backup_state: Option<bool>,
    pub attestation_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: i64,
    pub aaguid: Option<Uuid>,
    pub credential_type: String,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: Option<bool>,
    pub backup_state: Option<bool>,
    pub attestation_type: Option<String>,
}