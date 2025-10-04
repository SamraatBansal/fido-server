//! Input validation utilities

use regex::Regex;
use uuid::Uuid;

/// Validate username format
pub fn validate_username(username: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    
    if username.len() < 3 {
        return Err("Username must be at least 3 characters long".to_string());
    }
    
    if username.len() > 50 {
        return Err("Username cannot exceed 50 characters".to_string());
    }
    
    // Allow alphanumeric characters, dots, hyphens, and underscores
    let username_regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    
    if !username_regex.is_match(username) {
        return Err("Username can only contain alphanumeric characters, dots, hyphens, and underscores".to_string());
    }
    
    Ok(())
}

/// Validate display name format
pub fn validate_display_name(display_name: &str) -> Result<(), String> {
    if display_name.is_empty() {
        return Err("Display name cannot be empty".to_string());
    }
    
    if display_name.len() > 100 {
        return Err("Display name cannot exceed 100 characters".to_string());
    }
    
    // Allow most characters but control characters
    if display_name.chars().any(|c| c.is_control()) {
        return Err("Display name cannot contain control characters".to_string());
    }
    
    Ok(())
}

/// Validate UUID format
pub fn validate_uuid(uuid_str: &str) -> Result<Uuid, String> {
    Uuid::parse_str(uuid_str).map_err(|_| "Invalid UUID format".to_string())
}

/// Validate base64 string
pub fn validate_base64(base64_str: &str) -> Result<(), String> {
    base64::decode(base64_str).map_err(|_| "Invalid base64 format".to_string())?;
    Ok(())
}

/// Validate URL format
pub fn validate_url(url_str: &str) -> Result<(), String> {
    url::Url::parse(url_str).map_err(|_| "Invalid URL format".to_string())?;
    Ok(())
}

/// Validate email format (basic validation)
pub fn validate_email(email: &str) -> Result<(), String> {
    if email.is_empty() {
        return Err("Email cannot be empty".to_string());
    }
    
    if email.len() > 254 {
        return Err("Email cannot exceed 254 characters".to_string());
    }
    
    // Basic email regex (not perfect but good enough for basic validation)
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    
    if !email_regex.is_match(email) {
        return Err("Invalid email format".to_string());
    }
    
    Ok(())
}

/// Validate session token format
pub fn validate_session_token(token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("Session token cannot be empty".to_string());
    }
    
    if token.len() < 10 {
        return Err("Session token too short".to_string());
    }
    
    if token.len() > 1000 {
        return Err("Session token too long".to_string());
    }
    
    // Should be base64 URL-safe
    let token_regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    
    if !token_regex.is_match(token) {
        return Err("Session token contains invalid characters".to_string());
    }
    
    Ok(())
}

/// Sanitize string input
pub fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("user_name").is_ok());
        
        assert!(validate_username("").is_err());
        assert!(validate_username("us").is_err()); // Too short
        assert!(validate_username("user@name").is_err()); // Invalid character
    }

    #[test]
    fn test_validate_display_name() {
        assert!(validate_display_name("John Doe").is_ok());
        assert!(validate_display_name("用户").is_ok()); // Unicode characters
        
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("John\u{0}Doe").is_err()); // Control character
    }

    #[test]
    fn test_validate_uuid() {
        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(validate_uuid(valid_uuid).is_ok());
        
        assert!(validate_uuid("invalid-uuid").is_err());
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name@example.co.uk").is_ok());
        
        assert!(validate_email("").is_err());
        assert!(validate_email("invalid-email").is_err());
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("  hello world  "), "hello world");
        assert_eq!(sanitize_string("hello\u{0}world"), "helloworld");
        assert_eq!(sanitize_string(""), "");
    }
}