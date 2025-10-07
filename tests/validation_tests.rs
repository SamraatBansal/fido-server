#[cfg(test)]
mod tests {
    use super::*;
    use fido_server::utils::{validate_username, validate_display_name, validate_session_id, validate_credential_id};

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("testuser").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("test-user").is_ok());
        assert!(validate_username("user123").is_ok());

        // Invalid usernames
        assert!(validate_username("").is_err()); // Too short
        assert!(validate_username("ab").is_err()); // Too short
        assert!(validate_username("a".repeat(51).as_str()).is_err()); // Too long
        assert!(validate_username("test@user").is_err()); // Invalid character
        assert!(validate_username("test user").is_err()); // Space
    }

    #[test]
    fn test_validate_display_name() {
        // Valid display names
        assert!(validate_display_name("Test User").is_ok());
        assert!(validate_display_name("John Doe").is_ok());
        assert!(validate_display_name("用户").is_ok()); // Unicode

        // Invalid display names
        assert!(validate_display_name("").is_err()); // Empty
        assert!(validate_display_name("   ").is_err()); // Whitespace only
        assert!(validate_display_name("a".repeat(256).as_str()).is_err()); // Too long
    }

    #[test]
    fn test_validate_session_id() {
        // Valid session IDs
        assert!(validate_session_id("a".repeat(16).as_str()).is_ok());
        assert!(validate_session_id("a".repeat(100).as_str()).is_ok());
        assert!(validate_session_id("session-token-123").is_ok());

        // Invalid session IDs
        assert!(validate_session_id("a".repeat(15).as_str()).is_err()); // Too short
        assert!(validate_session_id("a".repeat(257).as_str()).is_err()); // Too long
    }

    #[test]
    fn test_validate_credential_id() {
        // Valid credential IDs (base64url encoded)
        assert!(validate_credential_id("dGVzdC1jcmVkZW50aWFsLWlk").is_ok());
        assert!(validate_credential_id("aGVsbG8td29ybGQ").is_ok());

        // Invalid credential IDs
        assert!(validate_credential_id("").is_err()); // Empty
        assert!(validate_credential_id("a".repeat(1025).as_str()).is_err()); // Too long
        assert!(validate_credential_id("invalid@base64").is_err()); // Invalid base64
    }
}