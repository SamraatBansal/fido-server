//! Database models using Diesel ORM

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::schema::*;

/// User model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    /// Primary key
    pub id: Uuid,
    /// Unique username
    pub username: String,
    /// Display name for the user
    pub display_name: String,
    /// User creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// New user for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

/// Credential model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    /// Primary key
    pub id: Uuid,
    /// Foreign key to user
    pub user_id: Uuid,
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// Credential public key (JSON)
    pub public_key: serde_json::Value,
    /// Signature counter
    pub sign_count: i64,
    /// AAGUID of authenticator
    pub aaguid: Option<String>,
    /// Attestation statement (JSON)
    pub attestation_statement: Option<serde_json::Value>,
    /// Whether credential is backed up
    pub backup_eligible: bool,
    /// Whether credential is currently backed up
    pub backup_state: bool,
    /// Whether clone was detected
    pub clone_warning: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// New credential for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: serde_json::Value,
    pub sign_count: i64,
    pub aaguid: Option<String>,
    pub attestation_statement: Option<serde_json::Value>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub clone_warning: bool,
}

/// Challenge model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    /// Primary key
    pub id: Uuid,
    /// Unique challenge identifier
    pub challenge_id: Uuid,
    /// Challenge data (base64 encoded)
    pub challenge_data: String,
    /// Optional user ID
    pub user_id: Option<Uuid>,
    /// Challenge type (registration/authentication)
    pub challenge_type: String,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Whether challenge has been used
    pub used: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Optional metadata (JSON)
    pub metadata: Option<serde_json::Value>,
}

/// New challenge for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge_id: Uuid,
    pub challenge_data: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

/// Session model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    /// Primary key
    pub id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Session token
    pub session_token: String,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    pub last_accessed_at: DateTime<Utc>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
}

/// New session for insertion
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = sessions)]
pub struct NewSession {
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Audit log model
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = audit_logs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuditLog {
    /// Primary key
    pub id: Uuid,
    /// User ID (optional)
    pub user_id: Option<Uuid>,
    /// Action performed
    pub action: String,
    /// Whether action was successful
    pub success: bool,
    /// Credential ID (optional)
    pub credential_id: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Error message (if any)
    pub error_message: Option<String>,
    /// Additional metadata (JSON)
    pub metadata: Option<serde_json::Value>,
    /// Timestamp
    pub created_at: DateTime<Utc>,
}

/// New audit log entry
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = audit_logs)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub action: String,
    pub success: bool,
    pub credential_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl From<User> for webauthn_rs::prelude::UserId {
    fn from(user: User) -> Self {
        webauthn_rs::prelude::UserId {
            name: user.username,
            display_name: user.display_name,
            id: user.id.as_bytes().to_vec(),
        }
    }
}

impl From<Credential> for webauthn_rs::prelude::CredentialID {
    fn from(credential: Credential) -> Self {
        webauthn_rs::prelude::CredentialID::from_bytes(
            &base64::decode(&credential.credential_id).unwrap_or_default()
        )
    }
}