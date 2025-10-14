//! Database models for FIDO Server

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::*;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_format: String,
    pub attestation_statement: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_format: String,
    pub attestation_statement: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i64>,
    pub backup_state: Option<bool>,
    pub user_verified: Option<bool>,
    pub updated_at: DateTime<Utc>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct UpdateChallenge {
    pub used: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = attestation_metadata)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AttestationMetadata {
    pub id: Uuid,
    pub aaguid: Vec<u8>,
    pub metadata_statement: Vec<u8>,
    pub status_report: Vec<String>,
    pub last_updated: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = attestation_metadata)]
pub struct NewAttestationMetadata {
    pub aaguid: Vec<u8>,
    pub metadata_statement: Vec<u8>,
    pub status_report: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = audit_logs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource: String,
    pub ip_address: std::net::IpAddr,
    pub user_agent: String,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = audit_logs)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource: String,
    pub ip_address: std::net::IpAddr,
    pub user_agent: String,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Attestation,
    Assertion,
}

impl From<ChallengeType> for String {
    fn from(challenge_type: ChallengeType) -> Self {
        match challenge_type {
            ChallengeType::Attestation => "attestation".to_string(),
            ChallengeType::Assertion => "assertion".to_string(),
        }
    }
}

impl From<String> for ChallengeType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "attestation" => ChallengeType::Attestation,
            "assertion" => ChallengeType::Assertion,
            _ => panic!("Invalid challenge type: {}", s),
        }
    }
}