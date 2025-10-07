//! Schema validation unit tests

use fido_server::schema::registration::{
    RegistrationStartRequest, RegistrationFinishRequest, PublicKeyCredential,
    AuthenticatorAttestationResponse, AuthenticatorSelection
};
use fido_server::schema::authentication::{
    AuthenticationStartRequest, AuthenticationFinishRequest, PublicKeyCredentialAssertion,
    AuthenticatorAssertionResponse
};
use fido_server::schema::common::{ErrorResponse, HealthResponse, SuccessResponse};
use fido_server::schema::user::User;
use fido_server::schema::credential::Credential;
use fido_server::schema::challenge::{Challenge, ChallengeType};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_start_request_validation() {
        // Valid request
        let valid_request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            attestation: Some("direct".to_string()),
            authenticator_selection: Some(AuthenticatorSelection {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
            }),
        };

        // Should serialize and deserialize correctly
        let serialized = serde_json::to_string(&valid_request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.username, valid_request.username);
        assert_eq!(deserialized.display_name, valid_request.display_name);
    }

    #[test]
    fn test_registration_start_request_minimal() {
        // Minimal valid request
        let minimal_request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            attestation: None,
            authenticator_selection: None,
        };

        let serialized = serde_json::to_string(&minimal_request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.username, minimal_request.username);
        assert!(deserialized.attestation.is_none());
        assert!(deserialized.authenticator_selection.is_none());
    }

    #[test]
    fn test_public_key_credential_validation() {
        let credential = PublicKeyCredential {
            id: "test-credential-id".to_string(),
            raw_id: "dGVzdC1jcmVkZW50aWFsLWlk".to_string(),
            response: AuthenticatorAttestationResponse {
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGdhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==".to_string(),
            },
            credential_type: "public-key".to_string(),
        };

        // Test serialization
        let serialized = serde_json::to_string(&credential).unwrap();
        let deserialized: PublicKeyCredential = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.id, credential.id);
        assert_eq!(deserialized.credential_type, "public-key");
        assert_eq!(deserialized.response.attestation_object, credential.response.attestation_object);
    }

    #[test]
    fn test_authentication_start_request_validation() {
        let request = AuthenticationStartRequest {
            username: "test@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: AuthenticationStartRequest = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.username, request.username);
        assert_eq!(deserialized.user_verification, request.user_verification);
    }

    #[test]
    fn test_public_key_credential_assertion_validation() {
        let assertion = PublicKeyCredentialAssertion {
            id: "test-credential-id".to_string(),
            raw_id: "dGVzdC1jcmVkZW50aWFsLWlk".to_string(),
            response: AuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ==".to_string(),
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==".to_string(),
                signature: "MEUCIQCdwBCYm5PjT_Q-wwOuyRvEYR_8f2vHqGhJp3b7b8jwIgYKqL8xRf9N8f2vHqGhJp3b7b8jwYKqL8xRf9N8f2vHqGhJp3b7b8jw".to_string(),
                user_handle: Some("dGVzdC11c2VyLWhhbmRsZQ==".to_string()),
            },
            credential_type: "public-key".to_string(),
        };

        let serialized = serde_json::to_string(&assertion).unwrap();
        let deserialized: PublicKeyCredentialAssertion = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.id, assertion.id);
        assert_eq!(deserialized.credential_type, "public-key");
        assert!(deserialized.response.user_handle.is_some());
    }

    #[test]
    fn test_error_response_creation() {
        let error = ErrorResponse::bad_request("Invalid input");
        assert_eq!(error.status, 400);
        assert_eq!(error.error, "Invalid input");
        assert!(error.timestamp.is_some());
        assert!(error.request_id.is_some());

        let not_found = ErrorResponse::not_found("User not found");
        assert_eq!(not_found.status, 404);

        let internal = ErrorResponse::internal_error("Database error");
        assert_eq!(internal.status, 500);
    }

    #[test]
    fn test_health_response_creation() {
        let health = HealthResponse::new("1.0.0".to_string());
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, "1.0.0");
        assert!(!health.timestamp.is_empty());

        let unhealthy = HealthResponse::unhealthy("1.0.0".to_string());
        assert_eq!(unhealthy.status, "unhealthy");
    }

    #[test]
    fn test_success_response_creation() {
        let success = SuccessResponse::new();
        assert_eq!(success.status, "success");
        assert!(success.message.is_none());

        let with_message = SuccessResponse::with_message("Operation completed");
        assert_eq!(with_message.status, "success");
        assert_eq!(with_message.message, Some("Operation completed".to_string()));
    }

    #[test]
    fn test_user_schema_validation() {
        let user = User::new(
            "test@example.com".to_string(),
            "Test User".to_string(),
        );

        // Valid user should pass validation
        assert!(user.validate().is_ok());

        // Test serialization
        let serialized = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.username, user.username);
        assert_eq!(deserialized.display_name, user.display_name);
    }

    #[test]
    fn test_credential_schema_validation() {
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            uuid::Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string(), "nfc".to_string()],
        );

        // Valid credential should pass validation
        assert!(credential.validate().is_ok());

        // Test serialization
        let serialized = serde_json::to_string(&credential).unwrap();
        let deserialized: Credential = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, credential.id);
        assert_eq!(deserialized.attestation_format, credential.attestation_format);
    }

    #[test]
    fn test_challenge_schema_validation() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = uuid::Uuid::new_v4();
        
        let registration_challenge = Challenge::registration(challenge_data.clone(), user_id);
        assert!(matches!(registration_challenge.challenge_type, ChallengeType::Registration));
        assert!(!registration_challenge.is_expired());

        let authentication_challenge = Challenge::authentication(challenge_data, user_id);
        assert!(matches!(authentication_challenge.challenge_type, ChallengeType::Authentication));
        assert!(!authentication_challenge.is_expired());

        // Test serialization
        let serialized = serde_json::to_string(&registration_challenge).unwrap();
        let deserialized: Challenge = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.challenge_type, registration_challenge.challenge_type);
    }

    #[test]
    fn test_invalid_base64url_handling() {
        // Test that invalid base64url strings are handled properly
        let invalid_credential = PublicKeyCredential {
            id: "invalid-base64!".to_string(), // Contains invalid character
            raw_id: "invalid-base64!".to_string(),
            response: AuthenticatorAttestationResponse {
                attestation_object: "invalid".to_string(),
                client_data_json: "invalid".to_string(),
            },
            credential_type: "public-key".to_string(),
        };

        // Should still serialize (we're not validating base64url in serialization)
        let serialized = serde_json::to_string(&invalid_credential).unwrap();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_empty_values_handling() {
        // Test empty strings in optional fields
        let request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            attestation: Some("".to_string()), // Empty string
            authenticator_selection: None,
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.attestation, Some("".to_string()));
    }

    #[test]
    fn test_large_payload_handling() {
        // Test handling of large display names
        let large_display_name = "a".repeat(255);
        let request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: large_display_name.clone(),
            attestation: None,
            authenticator_selection: None,
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.display_name, large_display_name);
    }

    #[test]
    fn test_special_characters_handling() {
        // Test handling of special characters in usernames and display names
        let request = RegistrationStartRequest {
            username: "test+tag@example.com".to_string(),
            display_name: "Test User Ñáéíóú".to_string(),
            attestation: None,
            authenticator_selection: None,
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.username, request.username);
        assert_eq!(deserialized.display_name, request.display_name);
    }
}