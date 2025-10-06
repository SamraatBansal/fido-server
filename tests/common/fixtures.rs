//! Test fixtures and data factories

use fido_server::{RegistrationRequest, AuthenticationRequest};
use uuid::Uuid;

/// Create a valid registration request for testing
pub fn valid_registration_request() -> RegistrationRequest {
    RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
    }
}

/// Create a registration request with custom username
pub fn registration_request_with_username(username: &str) -> RegistrationRequest {
    RegistrationRequest {
        username: username.to_string(),
        display_name: "Test User".to_string(),
    }
}

/// Create a registration request with custom display name
pub fn registration_request_with_display_name(display_name: &str) -> RegistrationRequest {
    RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: display_name.to_string(),
    }
}

/// Create a valid authentication request for testing
pub fn valid_authentication_request() -> AuthenticationRequest {
    AuthenticationRequest {
        username: "test@example.com".to_string(),
    }
}

/// Create an authentication request with custom username
pub fn authentication_request_with_username(username: &str) -> AuthenticationRequest {
    AuthenticationRequest {
        username: username.to_string(),
    }
}

/// Generate a random username for testing
pub fn random_username() -> String {
    format!("test{}@example.com", Uuid::new_v4().simple())
}

/// Generate a random display name for testing
pub fn random_display_name() -> String {
    format!("Test User {}", Uuid::new_v4().simple())
}

/// Create an invalid registration request (empty username)
pub fn invalid_registration_request_empty_username() -> RegistrationRequest {
    RegistrationRequest {
        username: "".to_string(),
        display_name: "Test User".to_string(),
    }
}

/// Create an invalid registration request (empty display name)
pub fn invalid_registration_request_empty_display_name() -> RegistrationRequest {
    RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "".to_string(),
    }
}

/// Create an invalid authentication request (empty username)
pub fn invalid_authentication_request() -> AuthenticationRequest {
    AuthenticationRequest {
        username: "".to_string(),
    }
}

/// Create a registration request with very long username
pub fn registration_request_long_username() -> RegistrationRequest {
    RegistrationRequest {
        username: "a".repeat(300),
        display_name: "Test User".to_string(),
    }
}

/// Create a registration request with very long display name
pub fn registration_request_long_display_name() -> RegistrationRequest {
    RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "a".repeat(300),
    }
}

/// Create a registration request with special characters
pub fn registration_request_special_chars() -> RegistrationRequest {
    RegistrationRequest {
        username: "test+special@example.com".to_string(),
        display_name: "Test User-Special".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_creation() {
        let reg_req = valid_registration_request();
        assert!(!reg_req.username.is_empty());
        assert!(!reg_req.display_name.is_empty());

        let auth_req = valid_authentication_request();
        assert!(!auth_req.username.is_empty());
    }

    #[test]
    fn test_random_generation() {
        let username1 = random_username();
        let username2 = random_username();
        assert_ne!(username1, username2);

        let display1 = random_display_name();
        let display2 = random_display_name();
        assert_ne!(display1, display2);
    }

    #[test]
    fn test_invalid_fixtures() {
        let empty_username = invalid_registration_request_empty_username();
        assert!(empty_username.username.is_empty());
        assert!(!empty_username.display_name.is_empty());

        let empty_display = invalid_registration_request_empty_display_name();
        assert!(!empty_display.username.is_empty());
        assert!(empty_display.display_name.is_empty());

        let invalid_auth = invalid_authentication_request();
        assert!(invalid_auth.username.is_empty());
    }
}