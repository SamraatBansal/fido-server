use base64::Engine as _;
use regex::Regex;
use validator::ValidationError;

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[a-zA-Z0-9_-]{3,50}$").unwrap();

    if !re.is_match(username) {
        return Err(ValidationError::new("invalid_username"));
    }

    Ok(())
}

pub fn validate_display_name(display_name: &str) -> Result<(), ValidationError> {
    if display_name.trim().is_empty() || display_name.len() > 255 {
        return Err(ValidationError::new("invalid_display_name"));
    }

    Ok(())
}

pub fn validate_session_id(session_id: &str) -> Result<(), ValidationError> {
    if session_id.len() < 16 || session_id.len() > 256 {
        return Err(ValidationError::new("invalid_session_id"));
    }

    Ok(())
}

pub fn validate_credential_id(credential_id: &str) -> Result<(), ValidationError> {
    // Should be base64url encoded
    if credential_id.is_empty() || credential_id.len() > 1024 {
        return Err(ValidationError::new("invalid_credential_id"));
    }

    // Try to decode as base64url
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential_id)
        .map_err(|_| ValidationError::new("invalid_credential_id_encoding"))?;

    Ok(())
}

pub fn sanitize_input(input: &str) -> String {
    // Basic XSS prevention
    input
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('&', "&amp;")
}

pub fn is_safe_origin(origin: &str, allowed_origins: &[String]) -> bool {
    allowed_origins
        .iter()
        .any(|allowed| allowed == "*" || allowed == origin)
}

pub fn generate_secure_random_bytes(length: usize) -> Result<Vec<u8>, rand::Error> {
    let mut bytes = vec![0u8; length];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}
