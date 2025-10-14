use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::credentials;

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verification_policy: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verification_policy: String,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
}

#[derive(Debug, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i64>,
    pub last_used: Option<DateTime<Utc>>,
    pub backup_state: Option<bool>,
}

impl Credential {
    pub fn new(
        user_id: Uuid,
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        attestation_format: String,
        aaguid: Option<Vec<u8>>,
        sign_count: i64,
        user_verification_policy: String,
        backup_eligible: bool,
        backup_state: bool,
        transports: Option<serde_json::Value>,
    ) -> NewCredential {
        NewCredential {
            user_id,
            credential_id,
            credential_public_key,
            attestation_format,
            aaguid,
            sign_count,
            user_verification_policy,
            backup_eligible,
            backup_state,
            transports,
        }
    }
}