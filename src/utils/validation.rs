//! Validation utilities

use base64::Engine;
use validator::ValidationError;

/// Validate attestation conveyance preference
pub fn validate_attestation(attestation: &str) -> Result<(), ValidationError> {
    match attestation {
        "none" | "direct" | "indirect" | "enterprise" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_attestation");
            error.message = Some("Attestation must be one of: none, direct, indirect, enterprise".into());
            Err(error)
        }
    }
}

/// Validate authenticator attachment
pub fn validate_authenticator_attachment(attachment: &str) -> Result<(), ValidationError> {
    match attachment {
        "platform" | "cross-platform" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_attachment");
            error.message = Some("Authenticator attachment must be 'platform' or 'cross-platform'".into());
            Err(error)
        }
    }
}

/// Validate user verification requirement
pub fn validate_user_verification(uv: &str) -> Result<(), ValidationError> {
    match uv {
        "required" | "preferred" | "discouraged" => Ok(()),
        _ => {
            let mut error = ValidationError::new("invalid_user_verification");
            error.message = Some("User verification must be one of: required, preferred, discouraged".into());
            Err(error)
        }
    }
}

/// Validate base64url encoding
pub fn validate_base64url(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("empty_base64url"));
    }

    // Check for invalid base64url characters
    if value.contains('+') || value.contains('/') || value.contains('=') {
        return Err(ValidationError::new("invalid_base64url_chars"));
    }

    // Try to decode
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ValidationError::new("invalid_base64url_decode"))?;

    Ok(())
}

/// Validate credential type
pub fn validate_credential_type(credential_type: &str) -> Result<(), ValidationError> {
    if credential_type != "public-key" {
        let mut error = ValidationError::new("invalid_credential_type");
        error.message = Some("Credential type must be 'public-key'".into());
        Err(error)
    } else {
        Ok(())
    }
}