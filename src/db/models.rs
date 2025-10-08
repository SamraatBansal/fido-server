//! Database models for FIDO2/WebAuthn server

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::schema::*;



/// User model representing a FIDO2/WebAuthn user
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    /// Primary key
    pub id: Uuid,
    /// Unique username
    pub username: String,
    /// Display name for user interface
    pub display_name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Whether the user is active
    pub is_active: bool,
}

/// New user for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
}

/// Credential model representing a WebAuthn credential
#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct Credential {
    /// Primary key
    pub id: Uuid,
    /// Foreign key to user
    pub user_id: Uuid,
    /// Credential ID (binary)
    pub credential_id: Vec<u8>,
    /// Public key (binary)
    pub public_key: Vec<u8>,
    /// Attestation format
    pub attestation_format: Option<String>,
    /// Authenticator AAGUID
    pub aaguid: Option<Uuid>,
    /// Signature counter
    pub sign_count: i64,
    /// Whether backup is eligible
    pub backup_eligible: bool,
    /// Current backup state
    pub backup_state: bool,
    /// Supported transports (JSON)
    pub transports: Option<serde_json::Value>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last usage timestamp
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether the credential is active
    pub is_active: bool,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_format: Option<String>,
    pub aaguid: Option<Uuid>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<String>,
    pub is_active: bool,
}

/// Challenge model for registration/authentication challenges
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    /// Primary key
    pub id: Uuid,
    /// Challenge in base64 encoding
    pub challenge_base64: String,
    /// Foreign key to user (optional for username-less auth)
    pub user_id: Option<Uuid>,
    /// Challenge type: 'registration' or 'authentication'
    pub challenge_type: String,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// When the challenge was used
    pub used_at: Option<DateTime<Utc>>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge_base64: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}