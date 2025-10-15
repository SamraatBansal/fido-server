//! Database Models
//! 
//! Data models for FIDO2/WebAuthn server with security considerations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use diesel::prelude::*;

/// User model representing FIDO2/WebAuthn users
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    /// Primary key
    pub id: Uuid,
    /// Unique username (email format recommended)
    pub username: String,
    /// Display name for user interface
    pub display_name: String,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// New user creation data
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

/// User update data
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct UpdateUser {
    pub display_name: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Credential model for WebAuthn credentials
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    /// Primary key
    pub id: Uuid,
    /// Foreign key to user
    pub user_id: Uuid,
    /// WebAuthn credential ID (binary)
    pub credential_id: Vec<u8>,
    /// Public key in COSE format
    pub credential_public_key: Vec<u8>,
    /// Attestation format type
    pub attestation_type: String,
    /// Authenticator AAGUID
    pub aaguid: Option<Uuid>,
    /// Signature counter (for replay detection)
    pub sign_count: i64,
    /// Credential creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last successful authentication
    pub last_used_at: Option<DateTime<Utc>>,
    /// Supported transports (JSON array)
    pub transports: Option<serde_json::Value>,
    /// Backup eligible flag
    pub backup_eligible: bool,
    /// Current backup state
    pub backup_state: bool,
}

/// New credential creation data
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Uuid>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Credential update data
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i64>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_state: Option<bool>,
}

/// Challenge model for preventing replay attacks
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    /// Primary key
    pub id: Uuid,
    /// Cryptographically random challenge
    pub challenge: Vec<u8>,
    /// Associated user (optional for anonymous operations)
    pub user_id: Option<Uuid>,
    /// Challenge type: registration or authentication
    pub challenge_type: String,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// New challenge creation data
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

/// Authentication session for tracking login attempts
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::auth_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuthSession {
    /// Primary key
    pub id: Uuid,
    /// Associated user
    pub user_id: Uuid,
    /// Session token
    pub session_token: String,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Session expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity_at: DateTime<Utc>,
    /// Session status (active, expired, revoked)
    pub status: String,
}

/// New authentication session data
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::auth_sessions)]
pub struct NewAuthSession {
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

/// Security audit log for compliance
#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::audit_logs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuditLog {
    /// Primary key
    pub id: Uuid,
    /// Associated user (optional for system events)
    pub user_id: Option<Uuid>,
    /// Event type (registration, authentication, failure, etc.)
    pub event_type: String,
    /// Event description
    pub description: String,
    /// IP address of request
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Event timestamp
    pub created_at: DateTime<Utc>,
    /// Additional metadata (JSON)
    pub metadata: Option<serde_json::Value>,
}

/// New audit log entry
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::audit_logs)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl User {
    /// Validate user data for security compliance
    pub fn validate(&self) -> Result<(), String> {
        // Username validation
        if self.username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }

        if self.username.len() > 255 {
            return Err("Username too long (max 255 characters)".to_string());
        }

        // Basic email format validation
        if !self.username.contains('@') {
            return Err("Username should be in email format".to_string());
        }

        // Display name validation
        if self.display_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }

        if self.display_name.len() > 255 {
            return Err("Display name too long (max 255 characters)".to_string());
        }

        Ok(())
    }

    /// Check if user account is in valid state
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

impl Credential {
    /// Validate credential data for security compliance
    pub fn validate(&self) -> Result<(), String> {
        // Credential ID validation
        if self.credential_id.is_empty() {
            return Err("Credential ID cannot be empty".to_string());
        }

        if self.credential_id.len() > 1023 {
            return Err("Credential ID too long (max 1023 bytes)".to_string());
        }

        // Public key validation
        if self.credential_public_key.is_empty() {
            return Err("Public key cannot be empty".to_string());
        }

        // Sign count validation
        if self.sign_count < 0 {
            return Err("Sign count cannot be negative".to_string());
        }

        // Attestation type validation
        match self.attestation_type.as_str() {
            "packed" | "fido-u2f" | "none" | "android-key" | "android-safetynet" => Ok(()),
            _ => Err("Invalid attestation type".to_string()),
        }
    }

    /// Check if credential is expired (based on creation time)
    pub fn is_expired(&self, max_age_days: i64) -> bool {
        let now = Utc::now();
        let age = now.signed_duration_since(self.created_at);
        age.num_days() > max_age_days
    }

    /// Check if credential backup state is valid
    pub fn has_valid_backup_state(&self) -> bool {
        // If backup is not eligible, state should be false
        if !self.backup_eligible && self.backup_state {
            return false;
        }
        true
    }
}

impl Challenge {
    /// Validate challenge data
    pub fn validate(&self) -> Result<(), String> {
        // Challenge validation
        if self.challenge.is_empty() {
            return Err("Challenge cannot be empty".to_string());
        }

        if self.challenge.len() != 32 {
            return Err("Challenge must be exactly 32 bytes".to_string());
        }

        // Challenge type validation
        match self.challenge_type.as_str() {
            "registration" | "authentication" => Ok(()),
            _ => Err("Invalid challenge type".to_string()),
        }
    }

    /// Check if challenge has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if challenge is valid for use
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.validate().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_validation() {
        let user = User {
            id: Uuid::new_v4(),
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(user.validate().is_ok());
        assert!(user.is_valid());
    }

    #[test]
    fn test_user_validation_invalid_email() {
        let user = User {
            id: Uuid::new_v4(),
            username: "invalid-email".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(user.validate().is_err());
        assert!(!user.is_valid());
    }

    #[test]
    fn test_credential_validation() {
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: vec![1, 2, 3, 4],
            credential_public_key: vec![5, 6, 7, 8],
            attestation_type: "packed".to_string(),
            aaguid: Some(Uuid::new_v4()),
            sign_count: 0,
            created_at: Utc::now(),
            last_used_at: None,
            transports: None,
            backup_eligible: false,
            backup_state: false,
        };

        assert!(credential.validate().is_ok());
    }

    #[test]
    fn test_credential_invalid_attestation() {
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: vec![1, 2, 3, 4],
            credential_public_key: vec![5, 6, 7, 8],
            attestation_type: "invalid".to_string(),
            aaguid: Some(Uuid::new_v4()),
            sign_count: 0,
            created_at: Utc::now(),
            last_used_at: None,
            transports: None,
            backup_eligible: false,
            backup_state: false,
        };

        assert!(credential.validate().is_err());
    }

    #[test]
    fn test_challenge_validation() {
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: vec![0; 32], // 32 bytes of zeros
            user_id: Some(Uuid::new_v4()),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
        };

        assert!(challenge.validate().is_ok());
        assert!(challenge.is_valid());
    }

    #[test]
    fn test_challenge_invalid_length() {
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: vec![0; 16], // Wrong length
            user_id: Some(Uuid::new_v4()),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
        };

        assert!(challenge.validate().is_err());
    }

    #[test]
    fn test_challenge_expiration() {
        let expired_challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: vec![0; 32],
            user_id: Some(Uuid::new_v4()),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() - chrono::Duration::minutes(1), // Expired
            created_at: Utc::now(),
        };

        assert!(!expired_challenge.is_valid());
        assert!(expired_challenge.is_expired());
    }
}