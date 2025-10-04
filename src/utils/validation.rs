//! Input validation utilities

use regex::Regex;
use validator::{ValidationError, ValidationErrors};
use crate::error::{AppError, Result};

/// Validate username format
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(AppError::ValidationError("Username cannot be empty".to_string()));
    }

    if username.len() > 255 {
        return Err(AppError::ValidationError("Username too long (max 255 characters)".to_string()));
    }

    // Allow alphanumeric characters, dots, hyphens, and underscores
    let username_regex = Regex::new(r"^[a-zA-Z0-9._-]+$")
        .map_err(|e| AppError::InternalError(format!("Invalid username regex: {}", e)))?;

    if !username_regex.is_match(username) {
        return Err(AppError::ValidationError("Username contains invalid characters".to_string()));
    }

    // Prevent reserved usernames
    let reserved_usernames = vec![
        "admin", "administrator", "root", "system", "api", "www", "mail", "ftp",
        "support", "sales", "info", "contact", "about", "help", "service", "test",
        "demo", "guest", "user", "users", "account", "accounts", "profile", "profiles"
    ];

    if reserved_usernames.contains(&username.to_lowercase().as_str()) {
        return Err(AppError::ValidationError("Username is reserved".to_string()));
    }

    Ok(())
}

/// Validate display name format
pub fn validate_display_name(display_name: &str) -> Result<()> {
    if display_name.is_empty() {
        return Err(AppError::ValidationError("Display name cannot be empty".to_string()));
    }

    if display_name.len() > 255 {
        return Err(AppError::ValidationError("Display name too long (max 255 characters)".to_string()));
    }

    // Basic validation - no control characters
    if display_name.chars().any(|c| c.is_control()) {
        return Err(AppError::ValidationError("Display name contains invalid characters".to_string()));
    }

    // Check for suspicious patterns
    let suspicious_patterns = vec![
        r"<script.*?>.*?</script>", // Script tags
        r"javascript:", // JavaScript protocol
        r"data:", // Data protocol
        r"vbscript:", // VBScript protocol
    ];

    for pattern in suspicious_patterns {
        let regex = Regex::new(pattern)
            .map_err(|e| AppError::InternalError(format!("Invalid regex pattern: {}", e)))?;
        if regex.is_match(display_name) {
            return Err(AppError::ValidationError("Display name contains suspicious content".to_string()));
        }
    }

    Ok(())
}

/// Validate email format
pub fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(AppError::ValidationError("Email cannot be empty".to_string()));
    }

    if email.len() > 254 {
        return Err(AppError::ValidationError("Email too long (max 254 characters)".to_string()));
    }

    // Basic email regex (simplified)
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .map_err(|e| AppError::InternalError(format!("Invalid email regex: {}", e)))?;

    if !email_regex.is_match(email) {
        return Err(AppError::ValidationError("Invalid email format".to_string()));
    }

    // Check for suspicious patterns
    let suspicious_domains = vec![
        "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com"
    ];

    if let Some(domain) = email.split('@').nth(1) {
        if suspicious_domains.contains(&domain) {
            return Err(AppError::ValidationError("Disposable email addresses are not allowed".to_string()));
        }
    }

    Ok(())
}

/// Validate URL format
pub fn validate_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(AppError::ValidationError("URL cannot be empty".to_string()));
    }

    if url.len() > 2048 {
        return Err(AppError::ValidationError("URL too long (max 2048 characters)".to_string()));
    }

    // Basic URL validation
    let url_regex = Regex::new(r"^https?://[^\s/$.?#].[^\s]*$")
        .map_err(|e| AppError::InternalError(format!("Invalid URL regex: {}", e)))?;

    if !url_regex.is_match(url) {
        return Err(AppError::ValidationError("Invalid URL format".to_string()));
    }

    // Ensure HTTPS in production
    if !url.starts_with("https://") {
        return Err(AppError::ValidationError("Only HTTPS URLs are allowed".to_string()));
    }

    Ok(())
}

/// Validate WebAuthn credential ID
pub fn validate_credential_id(credential_id: &str) -> Result<()> {
    if credential_id.is_empty() {
        return Err(AppError::ValidationError("Credential ID cannot be empty".to_string()));
    }

    if credential_id.len() > 1024 {
        return Err(AppError::ValidationError("Credential ID too long".to_string()));
    }

    // Try to decode as base64url to validate format
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(credential_id)
        .map_err(|_| AppError::ValidationError("Invalid credential ID format".to_string()))?;

    Ok(())
}

/// Validate session token
pub fn validate_session_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(AppError::ValidationError("Session token cannot be empty".to_string()));
    }

    if token.len() < 32 {
        return Err(AppError::ValidationError("Session token too short".to_string()));
    }

    if token.len() > 512 {
        return Err(AppError::ValidationError("Session token too long".to_string()));
    }

    // Check for valid characters (base64url)
    let token_regex = Regex::new(r"^[a-zA-Z0-9_-]+$")
        .map_err(|e| AppError::InternalError(format!("Invalid token regex: {}", e)))?;

    if !token_regex.is_match(token) {
        return Err(AppError::ValidationError("Invalid session token format".to_string()));
    }

    Ok(())
}

/// Validate challenge ID
pub fn validate_challenge_id(challenge_id: &str) -> Result<()> {
    if challenge_id.is_empty() {
        return Err(AppError::ValidationError("Challenge ID cannot be empty".to_string()));
    }

    // Try to parse as UUID
    uuid::Uuid::parse_str(challenge_id)
        .map_err(|_| AppError::ValidationError("Invalid challenge ID format".to_string()))?;

    Ok(())
}

/// Sanitize HTML input (basic implementation)
pub fn sanitize_html(input: &str) -> String {
    // This is a very basic implementation
    // In production, use a proper HTML sanitizer library like ammonia
    let mut sanitized = input.to_string();
    
    // Remove script tags
    let script_regex = Regex::new(r"<script.*?>.*?</script>").unwrap();
    sanitized = script_regex.replace_all(&sanitized, "").to_string();
    
    // Remove dangerous attributes
    let dangerous_regex = Regex::new(r"on\w+\s*=").unwrap();
    sanitized = dangerous_regex.replace_all(&sanitized, "").to_string();
    
    sanitized
}

/// Validate JSON Web Token format
pub fn validate_jwt_format(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(AppError::ValidationError("JWT cannot be empty".to_string()));
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::ValidationError("Invalid JWT format".to_string()));
    }

    // Try to decode header and payload (not signature)
    for part in parts.iter().take(2) {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part)
            .map_err(|_| AppError::ValidationError("Invalid JWT base64 encoding".to_string()))?;
    }

    Ok(())
}

/// Validate IP address format
pub fn validate_ip_address(ip: &str) -> Result<()> {
    if ip.is_empty() {
        return Err(AppError::ValidationError("IP address cannot be empty".to_string()));
    }

    // Try to parse as IPv4 or IPv6
    if ip.parse::<std::net::Ipv4Addr>().is_ok() || ip.parse::<std::net::Ipv6Addr>().is_ok() {
        Ok(())
    } else {
        Err(AppError::ValidationError("Invalid IP address format".to_string()))
    }
}

/// Check for common attack patterns in input
pub fn check_attack_patterns(input: &str) -> Result<()> {
    let attack_patterns = vec![
        r"<script[^>]*>.*?</script>", // XSS
        r"javascript:", // XSS
        r"on\w+\s*=", // Event handlers
        r"union\s+select", // SQL Injection
        r"drop\s+table", // SQL Injection
        r"insert\s+into", // SQL Injection
        r"delete\s+from", // SQL Injection
        r"exec\s*\(", // Command injection
        r"eval\s*\(", // Code injection
        r"\.\./", // Path traversal
        r"%2e%2e%2f", // URL encoded path traversal
    ];

    for pattern in attack_patterns {
        let regex = Regex::new(pattern)
            .map_err(|e| AppError::InternalError(format!("Invalid attack pattern regex: {}", e)))?;
        if regex.is_match(&input.to_lowercase()) {
            return Err(AppError::ValidationError("Input contains potentially dangerous content".to_string()));
        }
    }

    Ok(())
}

/// Convert validator errors to AppError
pub fn validation_errors_to_app_error(errors: ValidationErrors) -> AppError {
    let error_messages: Vec<String> = errors
        .field_errors()
        .iter()
        .flat_map(|(field, field_errors)| {
            field_errors.iter().map(move |error| {
                format!("{}: {}", field, error.message.as_ref().unwrap_or(&"Invalid value".into()))
            })
        })
        .collect();

    AppError::ValidationError(error_messages.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username() {
        assert!(validate_username("validuser123").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());
        
        assert!(validate_username("").is_err());
        assert!(validate_username("invalid user").is_err());
        assert!(validate_username("admin").is_err()); // Reserved
        assert!(validate_username("a".repeat(256).as_str()).is_err()); // Too long
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name+tag@example.co.uk").is_ok());
        
        assert!(validate_email("").is_err());
        assert!(validate_email("invalid-email").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@tempmail.com").is_err()); // Disposable
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("https://www.example.com/path").is_ok());
        
        assert!(validate_url("").is_err());
        assert!(validate_url("http://example.com").is_err()); // HTTP not allowed
        assert!(validate_url("not-a-url").is_err());
    }

    #[test]
    fn test_validate_credential_id() {
        let valid_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"test_credential_id");
        assert!(validate_credential_id(&valid_id).is_ok());
        
        assert!(validate_credential_id("").is_err());
        assert!(validate_credential_id("invalid!base64").is_err());
    }

    #[test]
    fn test_sanitize_html() {
        let input = r#"<script>alert('xss')</script><p onclick="alert('xss')">Safe content</p>"#;
        let sanitized = sanitize_html(input);
        
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("onclick="));
        assert!(sanitized.contains("Safe content"));
    }

    #[test]
    fn test_check_attack_patterns() {
        assert!(check_attack_patterns("normal content").is_ok());
        assert!(check_attack_patterns("<script>alert('xss')</script>").is_err());
        assert!(check_attack_patterns("UNION SELECT * FROM users").is_err());
        assert!(check_attack_patterns("../../etc/passwd").is_err());
    }
}