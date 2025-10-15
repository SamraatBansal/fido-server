use crate::error::{AppError, Result};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

pub fn generate_challenge() -> String {
    let mut rng = rand::thread_rng();
    let challenge_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes)
}

pub fn generate_user_id() -> String {
    let mut rng = rand::thread_rng();
    let user_id_bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    general_purpose::URL_SAFE_NO_PAD.encode(&user_id_bytes)
}

pub fn validate_base64url(data: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| AppError::ValidationError("Invalid base64url encoding".to_string()))
}

pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(AppError::ValidationError("Username cannot be empty".to_string()));
    }
    
    if username.len() > 255 {
        return Err(AppError::ValidationError("Username too long".to_string()));
    }
    
    // Basic email validation
    if !username.contains('@') || !username.contains('.') {
        return Err(AppError::ValidationError("Invalid username format".to_string()));
    }
    
    Ok(())
}

pub fn validate_display_name(display_name: &str) -> Result<()> {
    if display_name.is_empty() {
        return Err(AppError::ValidationError("Display name cannot be empty".to_string()));
    }
    
    if display_name.len() > 255 {
        return Err(AppError::ValidationError("Display name too long".to_string()));
    }
    
    Ok(())
}

pub fn validate_user_verification(user_verification: &str) -> Result<()> {
    match user_verification {
        "required" | "preferred" | "discouraged" => Ok(()),
        _ => Err(AppError::ValidationError("Invalid user verification value".to_string())),
    }
}

pub fn validate_attestation(attestation: &str) -> Result<()> {
    match attestation {
        "none" | "indirect" | "direct" | "enterprise" => Ok(()),
        _ => Err(AppError::ValidationError("Invalid attestation value".to_string())),
    }
}

pub fn validate_authenticator_attachment(attachment: &str) -> Result<()> {
    match attachment {
        "platform" | "cross-platform" => Ok(()),
        _ => Err(AppError::ValidationError("Invalid authenticator attachment value".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        // Challenges should be different
        assert_ne!(challenge1, challenge2);
        
        // Should be valid base64url
        assert!(validate_base64url(&challenge1).is_ok());
        assert!(validate_base64url(&challenge2).is_ok());
        
        // Should decode to 32 bytes
        let decoded = validate_base64url(&challenge1).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_generate_user_id() {
        let user_id1 = generate_user_id();
        let user_id2 = generate_user_id();
        
        // User IDs should be different
        assert_ne!(user_id1, user_id2);
        
        // Should be valid base64url
        assert!(validate_base64url(&user_id1).is_ok());
        assert!(validate_base64url(&user_id2).is_ok());
        
        // Should decode to 16 bytes
        let decoded = validate_base64url(&user_id1).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("test@example.com").is_ok());
        assert!(validate_username("user.name@domain.org").is_ok());
        
        // Invalid usernames
        assert!(validate_username("").is_err());
        assert!(validate_username("invalid").is_err());
        assert!(validate_username("no-at-symbol.com").is_err());
        assert!(validate_username("no-dot@symbol").is_err());
        
        // Too long username
        let long_username = "a".repeat(256) + "@example.com";
        assert!(validate_username(&long_username).is_err());
    }

    #[test]
    fn test_validate_display_name() {
        // Valid display names
        assert!(validate_display_name("John Doe").is_ok());
        assert!(validate_display_name("Alice Smith").is_ok());
        assert!(validate_display_name("田中 倫").is_ok());
        
        // Invalid display names
        assert!(validate_display_name("").is_err());
        
        // Too long display name
        let long_name = "a".repeat(256);
        assert!(validate_display_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_user_verification() {
        // Valid values
        assert!(validate_user_verification("required").is_ok());
        assert!(validate_user_verification("preferred").is_ok());
        assert!(validate_user_verification("discouraged").is_ok());
        
        // Invalid values
        assert!(validate_user_verification("invalid").is_err());
        assert!(validate_user_verification("").is_err());
        assert!(validate_user_verification("REQUIRED").is_err());
    }

    #[test]
    fn test_validate_attestation() {
        // Valid values
        assert!(validate_attestation("none").is_ok());
        assert!(validate_attestation("indirect").is_ok());
        assert!(validate_attestation("direct").is_ok());
        assert!(validate_attestation("enterprise").is_ok());
        
        // Invalid values
        assert!(validate_attestation("invalid").is_err());
        assert!(validate_attestation("").is_err());
        assert!(validate_attestation("NONE").is_err());
    }

    #[test]
    fn test_validate_authenticator_attachment() {
        // Valid values
        assert!(validate_authenticator_attachment("platform").is_ok());
        assert!(validate_authenticator_attachment("cross-platform").is_ok());
        
        // Invalid values
        assert!(validate_authenticator_attachment("invalid").is_err());
        assert!(validate_authenticator_attachment("").is_err());
        assert!(validate_authenticator_attachment("PLATFORM").is_err());
    }

    #[test]
    fn test_validate_base64url() {
        // Valid base64url
        let valid_data = "SGVsbG8gV29ybGQ";
        assert!(validate_base64url(valid_data).is_ok());
        
        // Invalid base64url (contains padding)
        let invalid_data = "SGVsbG8gV29ybGQ=";
        assert!(validate_base64url(invalid_data).is_err());
        
        // Invalid base64url (invalid characters)
        let invalid_data2 = "SGVsbG8+V29ybGQ";
        assert!(validate_base64url(invalid_data2).is_err());
    }
}