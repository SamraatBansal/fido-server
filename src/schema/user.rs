//! User management API schemas

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// User creation request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    /// Username for the user
    #[validate(length(min = 3, max = 255), regex = "USERNAME_REGEX")]
    pub username: String,
    
    /// Display name for the user
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
}

/// User update request
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    /// Display name for the user
    #[validate(length(min = 1, max = 255))]
    pub display_name: Option<String>,
}

/// User response
#[derive(Debug, Serialize)]
pub struct UserResponse {
    /// User ID
    pub id: Uuid,
    
    /// Username
    pub username: String,
    
    /// Display name
    pub display_name: String,
    
    /// When the user was created
    pub created_at: DateTime<Utc>,
    
    /// When the user was last updated
    pub updated_at: DateTime<Utc>,
}

/// User with credentials response
#[derive(Debug, Serialize)]
pub struct UserWithCredentialsResponse {
    #[serde(flatten)]
    pub user: UserResponse,
    
    /// User's credentials
    pub credentials: Vec<CredentialSummaryResponse>,
}

/// Credential summary response
#[derive(Debug, Serialize)]
pub struct CredentialSummaryResponse {
    /// Credential ID
    pub id: Uuid,
    
    /// Credential ID (base64 encoded)
    pub credential_id: String,
    
    /// Attestation format
    pub attestation_format: String,
    
    /// When credential was created
    pub created_at: DateTime<Utc>,
    
    /// When credential was last used
    pub last_used_at: Option<DateTime<Utc>>,
    
    /// Whether credential is backup eligible
    pub backup_eligible: bool,
    
    /// Whether credential is backed up
    pub backup_state: bool,
    
    /// Supported transports
    pub transports: Option<Vec<String>>,
    
    /// Signature counter
    pub sign_count: i64,
}

/// Credential deletion response
#[derive(Debug, Serialize)]
pub struct DeleteCredentialResponse {
    /// Status of the deletion
    pub status: String,
    
    /// Message
    pub message: String,
}

/// Custom validation
mod validation {
    use lazy_static::lazy_static;
    use regex::Regex;
    use validator::ValidationError;

    lazy_static! {
        static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    }

    pub(crate) fn validate_username(username: &str) -> Result<(), ValidationError> {
        if USERNAME_REGEX.is_match(username) {
            Ok(())
        } else {
            let mut error = ValidationError::new("invalid_username");
            error.message = Some("Username can only contain letters, numbers, dots, hyphens, and underscores".into());
            Err(error)
        }
    }
}

// Re-export the regex for use in the struct
use validation::USERNAME_REGEX;