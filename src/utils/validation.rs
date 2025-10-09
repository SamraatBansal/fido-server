//! Validation utilities for WebAuthn operations

use lazy_static::lazy_static;
use regex::Regex;
use validator::{ValidationError, ValidationErrors};

lazy_static! {
    pub static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    pub static ref CREDENTIAL_ID_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    pub static ref BASE64URL_REGEX: Regex = Regex::new(r"^[A-Za-z0-9_-]*$").unwrap();
}

/// Validate attestation conveyance preference
pub fn validate_attestation(attestation: &str) -> Result<(), ValidationError> {
    match attestation {
        "none" | "indirect" | "direct" => Ok(()),
        _ => Err(ValidationError::new("invalid_attestation")),
    }
}

/// Validate user verification requirement
pub fn validate_user_verification(uv: &str) -> Result<(), ValidationError> {
    match uv {
        "required" | "preferred" | "discouraged" => Ok(()),
        _ => Err(ValidationError::new("invalid_user_verification")),
    }
}

/// Validate credential type
pub fn validate_credential_type(cred_type: &str) -> Result<(), ValidationError> {
    if cred_type == "public-key" {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_credential_type"))
    }
}

/// Validate base64url encoding
pub fn validate_base64url(data: &str) -> Result<(), ValidationError> {
    if BASE64URL_REGEX.is_match(data) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_base64url"))
    }
}

/// Validate challenge length and format
pub fn validate_challenge(challenge: &str) -> Result<(), ValidationError> {
    if challenge.len() < 16 || challenge.len() > 128 {
        return Err(ValidationError::new("invalid_challenge_length"));
    }
    
    if !BASE64URL_REGEX.is_match(challenge) {
        return Err(ValidationError::new("invalid_challenge_format"));
    }
    
    Ok(())
}

/// Validate credential ID format
pub fn validate_credential_id(id: &str) -> Result<(), ValidationError> {
    if id.is_empty() || id.len() > 1023 {
        return Err(ValidationError::new("invalid_credential_id_length"));
    }
    
    if !BASE64URL_REGEX.is_match(id) {
        return Err(ValidationError::new("invalid_credential_id_format"));
    }
    
    Ok(())
}

/// Validate authenticator data format
pub fn validate_authenticator_data(data: &str) -> Result<(), ValidationError> {
    if data.len() < 37 {
        return Err(ValidationError::new("invalid_authenticator_data_length"));
    }
    
    if !BASE64URL_REGEX.is_match(data) {
        return Err(ValidationError::new("invalid_authenticator_data_format"));
    }
    
    Ok(())
}

/// Validate signature format
pub fn validate_signature(signature: &str) -> Result<(), ValidationError> {
    if signature.is_empty() {
        return Err(ValidationError::new("empty_signature"));
    }
    
    if !BASE64URL_REGEX.is_match(signature) {
        return Err(ValidationError::new("invalid_signature_format"));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_attestation() {
        assert!(validate_attestation("none").is_ok());
        assert!(validate_attestation("indirect").is_ok());
        assert!(validate_attestation("direct").is_ok());
        assert!(validate_attestation("invalid").is_err());
    }

    #[test]
    fn test_validate_user_verification() {
        assert!(validate_user_verification("required").is_ok());
        assert!(validate_user_verification("preferred").is_ok());
        assert!(validate_user_verification("discouraged").is_ok());
        assert!(validate_user_verification("invalid").is_err());
    }

    #[test]
    fn test_validate_credential_type() {
        assert!(validate_credential_type("public-key").is_ok());
        assert!(validate_credential_type("invalid").is_err());
    }

    #[test]
    fn test_validate_challenge() {
        // Valid challenges
        assert!(validate_challenge("A".repeat(16).as_str()).is_ok());
        assert!(validate_challenge("A".repeat(64).as_str()).is_ok());
        
        // Invalid challenges
        assert!(validate_challenge("short").is_err()); // Too short
        assert!(validate_challenge(&"A".repeat(129)).is_err()); // Too long
        assert!(validate_challenge("invalid+chars").is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_base64url() {
        assert!(validate_base64url("valid_base64url_string123").is_ok());
        assert!(validate_base64url("invalid+chars").is_err());
        assert!(validate_base64url("invalid/chars").is_err());
        assert!(validate_base64url("invalid=padding").is_err());
    }
}