//! Database models for FIDO Server

use diesel::prelude::*;
use diesel::{SqlType, AsExpression, FromSqlRow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::db::schema::*;

/// Attestation type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationType {
    /// No attestation
    None,
    /// Basic attestation
    Basic,
    /// Self attestation
    SelfAttestation,
    /// AttCA attestation
    AttCa,
    /// Anonymous attestation
    Anonymous,
    /// Uncertain attestation
    Uncertain,
}

/// User verification type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserVerificationType {
    /// No user verification
    None,
    /// User presence only
    Presence,
    /// User verification required
    Required,
    /// User verification preferred
    Preferred,
    /// User verification discouraged
    Discouraged,
}

impl From<&str> for AttestationType {
    fn from(s: &str) -> Self {
        match s {
            "none" => AttestationType::None,
            "basic" => AttestationType::Basic,
            "self" => AttestationType::SelfAttestation,
            "attca" => AttestationType::AttCa,
            "anonymous" => AttestationType::Anonymous,
            "uncertain" => AttestationType::Uncertain,
            _ => AttestationType::None,
        }
    }
}

impl From<AttestationType> for &'static str {
    fn from(attestation_type: AttestationType) -> Self {
        match attestation_type {
            AttestationType::None => "none",
            AttestationType::Basic => "basic",
            AttestationType::SelfAttestation => "self",
            AttestationType::AttCa => "attca",
            AttestationType::Anonymous => "anonymous",
            AttestationType::Uncertain => "uncertain",
        }
    }
}

impl From<&str> for UserVerificationType {
    fn from(s: &str) -> Self {
        match s {
            "none" => UserVerificationType::None,
            "presence" => UserVerificationType::Presence,
            "required" => UserVerificationType::Required,
            "preferred" => UserVerificationType::Preferred,
            "discouraged" => UserVerificationType::Discouraged,
            _ => UserVerificationType::None,
        }
    }
}

impl From<UserVerificationType> for &'static str {
    fn from(uv_type: UserVerificationType) -> Self {
        match uv_type {
            UserVerificationType::None => "none",
            UserVerificationType::Presence => "presence",
            UserVerificationType::Required => "required",
            UserVerificationType::Preferred => "preferred",
            UserVerificationType::Discouraged => "discouraged",
        }
    }
}



/// User model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    /// User ID
    pub id: Uuid,
    /// Username
    pub username: String,
    /// Display name
    pub display_name: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

/// New user for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    /// Username
    pub username: String,
    /// Display name
    pub display_name: String,
}

/// Credential model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    /// Credential ID
    pub id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Credential ID (binary)
    pub credential_id: Vec<u8>,
    /// Public key (binary)
    pub public_key: Vec<u8>,
    /// Signature counter
    pub sign_count: i64,
    /// Attestation type
    pub attestation_type: String,
    /// Transports
    pub transports: Vec<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last used at
    pub last_used_at: Option<DateTime<Utc>>,
    /// Backup eligible
    pub backup_eligible: bool,
    /// Backup state
    pub backup_state: bool,
    /// User verification type
    pub user_verification_type: String,
    /// AAGUID
    pub aaguid: Option<Vec<u8>>,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    /// User ID
    pub user_id: Uuid,
    /// Credential ID (binary)
    pub credential_id: Vec<u8>,
    /// Public key (binary)
    pub public_key: Vec<u8>,
    /// Signature counter
    pub sign_count: i64,
    /// Attestation type
    pub attestation_type: String,
    /// Transports
    pub transports: Vec<String>,
    /// Backup eligible
    pub backup_eligible: bool,
    /// Backup state
    pub backup_state: bool,
    /// User verification type
    pub user_verification_type: String,
    /// AAGUID
    pub aaguid: Option<Vec<u8>>,
}

/// Challenge model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    /// Challenge ID
    pub id: Uuid,
    /// Challenge hash
    pub challenge_hash: String,
    /// User ID (optional)
    pub user_id: Option<Uuid>,
    /// Challenge type
    pub challenge_type: String,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Credential ID (optional)
    pub credential_id: Option<Vec<u8>>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    /// Challenge hash
    pub challenge_hash: String,
    /// User ID (optional)
    pub user_id: Option<Uuid>,
    /// Challenge type
    pub challenge_type: String,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Credential ID (optional)
    pub credential_id: Option<Vec<u8>>,
}

/// User with credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserWithCredentials {
    /// User information
    pub user: User,
    /// Credentials
    pub credentials: Vec<Credential>,
}