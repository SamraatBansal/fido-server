//! Registration API schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;

/// Request to start registration
#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationStartRequest {
    /// Username for the user
    #[validate(length(min = 3, max = 255), regex = "USERNAME_REGEX")]
    pub username: String,
    
    /// Display name for the user
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    
    /// User verification preference
    #[validate(custom = "validate_user_verification")]
    pub user_verification: Option<String>,
}

/// Response for registration start
#[derive(Debug, Serialize)]
pub struct RegistrationStartResponse {
    /// Challenge for the client
    pub challenge: String,
    
    /// User entity
    pub user: PublicKeyCredentialUserEntity,
    
    /// Public key credential parameters
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    
    /// Relying party entity
    pub rp: PublicKeyCredentialRpEntity,
    
    /// Authenticator selection criteria
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    
    /// Attestation preference
    pub attestation: String,
    
    /// Timeout in milliseconds
    pub timeout: u32,
}

/// Request to finish registration
#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationFinishRequest {
    /// Credential ID
    #[validate(length(min = 1))]
    pub id: String,
    
    /// Raw credential ID
    #[validate(length(min = 1))]
    pub raw_id: String,
    
    /// Response data
    #[validate]
    pub response: RegistrationFinishResponse,
    
    /// Authenticator attachment
    pub authenticator_attachment: Option<String>,
    
    /// Client extension results
    pub client_extension_results: Option<serde_json::Value>,
}

/// Registration finish response data
#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationFinishResponse {
    /// Client data JSON
    #[validate(length(min = 1))]
    pub client_data_json: String,
    
    /// Attestation object
    #[validate(length(min = 1))]
    pub attestation_object: String,
    
    /// Transports used
    pub transports: Option<Vec<String>>,
}

/// Response for registration finish
#[derive(Debug, Serialize)]
pub struct RegistrationFinishResponseData {
    /// Status of the registration
    pub status: String,
    
    /// Credential ID
    pub credential_id: String,
    
    /// User ID
    pub user_id: String,
    
    /// Message
    pub message: String,
}

/// Custom validation functions
mod validation {
    use lazy_static::lazy_static;
    use regex::Regex;
    use validator::{ValidationError, ValidationErrors};

    lazy_static! {
        static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    }

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

// Re-export the regex for use in the struct
use validation::USERNAME_REGEX;