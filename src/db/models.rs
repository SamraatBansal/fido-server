//! Database models for FIDO2/WebAuthn implementation

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::{challenges, credentials, users};

/// User model representing a registered user
#[derive(Queryable, Identifiable, Serialize, Debug, Clone, PartialEq)]
#[diesel(table_name = users)]
pub struct User {
    /// Primary key
    pub id: Uuid,
    /// Unique username
    pub username: String,
    /// Display name for the user
    pub display_name: String,
    /// When the user was created
    pub created_at: DateTime<Utc>,
    /// When the user was last updated
    pub updated_at: DateTime<Utc>,
}

/// New user for insertion
#[derive(Insertable, Debug, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

/// User update data
#[derive(AsChangeset, Debug, Deserialize)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub display_name: Option<String>,
}

/// Credential model representing a WebAuthn credential
#[derive(Queryable, Identifiable, Associations, Serialize, Debug, Clone, PartialEq)]
#[diesel(belongs_to(User))]
#[diesel(table_name = credentials)]
pub struct Credential {
    /// Primary key
    pub id: Uuid,
    /// Foreign key to user
    pub user_id: Uuid,
    /// Credential ID (binary)
    pub credential_id: Vec<u8>,
    /// Public key in COSE format
    pub credential_public_key: Vec<u8>,
    /// Attestation format (e.g., "packed", "fido-u2f", "none")
    pub attestation_format: String,
    /// Authenticator AAGUID
    pub aaguid: Option<Vec<u8>>,
    /// Signature counter
    pub sign_count: i64,
    /// Whether user verification was performed
    pub user_verification: bool,
    /// Whether credential is backup eligible
    pub backup_eligible: bool,
    /// Whether credential is backed up
    pub backup_state: bool,
    /// Supported transports
    pub transports: Option<Vec<String>>,
    /// When credential was created
    pub created_at: DateTime<Utc>,
    /// When credential was last used
    pub last_used_at: Option<DateTime<Utc>>,
}

/// New credential for insertion
#[derive(Insertable, Debug)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verification: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<Vec<String>>,
}

/// Credential update data
#[derive(AsChangeset, Debug)]
#[diesel(table_name = credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i64>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_state: Option<bool>,
}

/// Challenge model for replay attack prevention
#[derive(Queryable, Identifiable, Associations, Serialize, Debug, Clone, PartialEq)]
#[diesel(belongs_to(User))]
#[diesel(table_name = challenges)]
pub struct Challenge {
    /// Primary key
    pub id: Uuid,
    /// Challenge bytes (binary)
    pub challenge_bytes: Vec<u8>,
    /// Type of challenge: "registration" or "authentication"
    pub challenge_type: String,
    /// Associated user (optional for anonymous registration)
    pub user_id: Option<Uuid>,
    /// When challenge expires
    pub expires_at: DateTime<Utc>,
    /// When challenge was created
    pub created_at: DateTime<Utc>,
    /// Whether challenge has been used
    pub used: bool,
}

/// New challenge for insertion
#[derive(Insertable, Debug)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge_bytes: Vec<u8>,
    pub challenge_type: String,
    pub user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

/// Challenge update data
#[derive(AsChangeset, Debug)]
#[diesel(table_name = challenges)]
pub struct UpdateChallenge {
    pub used: Option<bool>,
}

/// User with credentials (for API responses)
#[derive(Serialize, Debug)]
pub struct UserWithCredentials {
    #[serde(flatten)]
    pub user: User,
    pub credentials: Vec<Credential>,
}

/// Credential summary for API responses
#[derive(Serialize, Debug)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub credential_id: String, // Base64 encoded
    pub attestation_format: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<Vec<String>>,
}

impl From<Credential> for CredentialSummary {
    fn from(credential: Credential) -> Self {
        Self {
            id: credential.id,
            credential_id: base64::encode(&credential.credential_id),
            attestation_format: credential.attestation_format,
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            transports: credential.transports,
        }
    }
}