//! Utility functions

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::{distributions::Alphanumeric, Rng};

/// Generate a random challenge for WebAuthn operations
pub fn generate_challenge() -> String {
    let mut rng = rand::thread_rng();
    let challenge: String = rng
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    BASE64.encode(challenge.as_bytes())
}

/// Validate base64 URL-safe encoding
pub fn validate_base64_url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Convert base64url to base64 if needed
    let base64_input = input
        .replace('-', "+")
        .replace('_', "/");
    
    // Add padding if needed
    let padded_input = match base64_input.len() % 4 {
        0 => base64_input,
        2 => format!("{}==", base64_input),
        3 => format!("{}=", base64_input),
        _ => return Err(base64::DecodeError::InvalidLength(0)),
    };
    
    BASE64.decode(padded_input)
}

/// Sanitize username input
pub fn sanitize_username(username: &str) -> String {
    username
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect::<String>()
        .to_lowercase()
        .trim()
        .to_string()
}

/// Validate display name
pub fn validate_display_name(display_name: &str) -> Result<(), String> {
    if display_name.trim().is_empty() {
        return Err("Display name cannot be empty".to_string());
    }
    
    if display_name.len() > 255 {
        return Err("Display name too long".to_string());
    }
    
    // Check for potentially dangerous characters
    if display_name.contains('<') || display_name.contains('>') {
        return Err("Display name contains invalid characters".to_string());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        assert_ne!(challenge1, challenge2);
        assert!(BASE64.decode(&challenge1).is_ok());
    }

    #[test]
    fn test_sanitize_username() {
        assert_eq!(sanitize_username("TestUser123"), "testuser123");
        assert_eq!(sanitize_username("Test@User#123"), "testuser123");
        assert_eq!(sanitize_username("  Test_User-123  "), "test_user-123");
    }

    #[test]
    fn test_validate_display_name() {
        assert!(validate_display_name("John Doe").is_ok());
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("John<script>").is_err());
    }
}