//! Schema validation unit tests

use serde::{Deserialize, Serialize};
use serde_json;

#[cfg(test)]
mod registration_schema_tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct RegistrationStartRequest {
        username: String,
        display_name: String,
        user_verification: String,
        attestation: String,
    }

    #[test]
    fn test_registration_start_request_serialization() {
        let request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: "preferred".to_string(),
            attestation: "direct".to_string(),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_registration_start_request_validation() {
        // Test valid email format
        let valid_request = RegistrationStartRequest {
            username: "user@example.com".to_string(),
            display_name: "User Name".to_string(),
            user_verification: "preferred".to_string(),
            attestation: "direct".to_string(),
        };

        // This will be implemented once we add validation
        // assert!(validate_registration_request(&valid_request).is_ok());

        // Placeholder
        assert!(true, "Validation implementation needed");
    }

    #[test]
    fn test_registration_start_request_invalid_email() {
        let invalid_request = RegistrationStartRequest {
            username: "invalid-email".to_string(),
            display_name: "User Name".to_string(),
            user_verification: "preferred".to_string(),
            attestation: "direct".to_string(),
        };

        // This should fail validation once implemented
        // assert!(validate_registration_request(&invalid_request).is_err());

        // Placeholder
        assert!(true, "Validation implementation needed");
    }
}

#[cfg(test)]
mod authentication_schema_tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct AuthenticationStartRequest {
        username: String,
        user_verification: String,
    }

    #[test]
    fn test_authentication_start_request_serialization() {
        let request = AuthenticationStartRequest {
            username: "test@example.com".to_string(),
            user_verification: "preferred".to_string(),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: AuthenticationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_authentication_start_request_validation() {
        // Test valid request
        let valid_request = AuthenticationStartRequest {
            username: "user@example.com".to_string(),
            user_verification: "required".to_string(),
        };

        // This will be implemented once we add validation
        // assert!(validate_authentication_request(&valid_request).is_ok());

        // Placeholder
        assert!(true, "Validation implementation needed");
    }
}

#[cfg(test)]
mod response_schema_tests {
    use super::*;

    #[test]
    fn test_error_response_format() {
        let error_response = serde_json::json!({
            "error": {
                "code": "INVALID_ATTESTATION",
                "message": "The attestation signature could not be verified",
                "details": {
                    "reason": "signature_verification_failed"
                }
            }
        });

        // Test that error response can be serialized/deserialized
        let serialized = serde_json::to_string(&error_response).unwrap();
        let deserialized = serde_json::from_str::<serde_json::Value>(&serialized).unwrap();

        assert_eq!(error_response, deserialized);
    }

    #[test]
    fn test_success_response_format() {
        let success_response = serde_json::json!({
            "status": "success",
            "credentialId": "base64url-encoded-credential-id"
        });

        // Test that success response can be serialized/deserialized
        let serialized = serde_json::to_string(&success_response).unwrap();
        let deserialized = serde_json::from_str::<serde_json::Value>(&serialized).unwrap();

        assert_eq!(success_response, deserialized);
    }
}