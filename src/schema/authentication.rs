//! Authentication API schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;

/// Request to start authentication
#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationStartRequest {
    /// Username for the user
    #[validate(length(min = 3, max = 255))]
    pub username: String,
    
    /// User verification preference
    #[validate(custom = "validate_user_verification")]
    pub user_verification: Option<String>,
}

/// Response for authentication start
#[derive(Debug, Serialize)]
pub struct AuthenticationStartResponse {
    /// Challenge for the client
    pub challenge: String,
    
    /// Allow credentials list
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    
    /// User verification requirement
    pub user_verification: String,
    
    /// Timeout in milliseconds
    pub timeout: u32,
    
    /// Relying party ID
    pub rp_id: String,
}

/// Request to finish authentication
#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationFinishRequest {
    /// Credential ID
    #[validate(length(min = 1))]
    pub id: String,
    
    /// Raw credential ID
    #[validate(length(min = 1))]
    pub raw_id: String,
    
    /// Response data
    #[validate]
    pub response: AuthenticationFinishResponse,
    
    /// Authenticator attachment
    pub authenticator_attachment: Option<String>,
    
    /// Client extension results
    pub client_extension_results: Option<serde_json::Value>,
}

/// Authentication finish response data
#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationFinishResponse {
    /// Client data JSON
    #[validate(length(min = 1))]
    pub client_data_json: String,
    
    /// Authenticator data
    #[validate(length(min = 1))]
    pub authenticator_data: String,
    
    /// Signature
    #[validate(length(min = 1))]
    pub signature: String,
    
    /// User handle
    pub user_handle: Option<String>,
}

/// Response for authentication finish
#[derive(Debug, Serialize)]
pub struct AuthenticationFinishResponseData {
    /// Status of the authentication
    pub status: String,
    
    /// User ID
    pub user_id: String,
    
    /// Username
    pub username: String,
    
    /// Display name
    pub display_name: String,
    
    /// Message
    pub message: String,
}

/// Custom validation functions
mod validation {
    use validator::ValidationError;

    pub(crate) fn validate_user_verification(
        user_verification: &str,
    ) -> Result<(), ValidationError> {
        match user_verification {
            "required" | "preferred" | "discouraged" => Ok(()),
            _ => {
                let mut error = ValidationError::new("invalid_user_verification");
                error.message = Some("User verification must be 'required', 'preferred', or 'discouraged'".into());
                Err(error)
            }
        }
    }
}