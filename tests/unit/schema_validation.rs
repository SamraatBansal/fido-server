//! Schema validation unit tests

#[cfg(test)]
mod tests {
    use fido_server::schema::registration::{
        RegistrationStartRequest, RegistrationFinishRequest, PublicKeyCredential,
        AuthenticatorSelection, AuthenticatorAttestationResponse
    };
    use fido_server::schema::authentication::{
        AuthenticationStartRequest, AuthenticationFinishRequest, PublicKeyCredentialAssertion,
        AuthenticatorAssertionResponse
    };
    use fido_server::schema::common::{ErrorResponse, HealthResponse};

    #[test]
    fn test_registration_start_request_validation() {
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

        // Test serialization
        let serialized = serde_json::to_string(&valid_request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, valid_request.username);
        assert_eq!(deserialized.display_name, valid_request.display_name);
    }

    #[test]
    fn test_public_key_credential_validation() {
        let credential = PublicKeyCredential {
            id: "test-credential-id".to_string(),
            raw_id: "dGVzdC1jcmVkZW50aWFsLWlk".to_string(),
            response: AuthenticatorAttestationResponse {
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==".to_string(),
            },
            credential_type: "public-key".to_string(),
        };

        // Test serialization
        let serialized = serde_json::to_string(&credential).unwrap();
        let deserialized: PublicKeyCredential = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, credential.id);
        assert_eq!(deserialized.credential_type, credential.credential_type);
    }

    #[test]
    fn test_authentication_start_request_validation() {
        let valid_request = AuthenticationStartRequest {
            username: "test@example.com".to_string(),
            user_verification: Some("preferred".to_string()),
        };

        // Test serialization
        let serialized = serde_json::to_string(&valid_request).unwrap();
        let deserialized: AuthenticationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, valid_request.username);
        assert_eq!(deserialized.user_verification, valid_request.user_verification);
    }

    #[test]
    fn test_public_key_credential_assertion_validation() {
        let assertion = PublicKeyCredentialAssertion {
            id: "test-assertion-id".to_string(),
            raw_id: "dGVzdC1hc3NlcnRpb24taWQ=".to_string(),
            response: AuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ==".to_string(),
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==".to_string(),
                signature: "MEUCIQCdwBCYm5PjT_Q-wwOuyRvEYR_8f2vHqGhJp3b7b8jwIgYKqL8xRf9N8f2vHqGhJp3b7b8jwYKqL8xRf9N8f2vHqGhJp3b7b8jw".to_string(),
                user_handle: Some("dGVzdC11c2VyLWhhbmRsZQ==".to_string()),
            },
            credential_type: "public-key".to_string(),
        };

        // Test serialization
        let serialized = serde_json::to_string(&assertion).unwrap();
        let deserialized: PublicKeyCredentialAssertion = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, assertion.id);
        assert_eq!(deserialized.credential_type, assertion.credential_type);
    }

    #[test]
    fn test_error_response_validation() {
        let error_response = ErrorResponse {
            error: fido_server::schema::common::ErrorDetails {
                code: "VALIDATION_ERROR".to_string(),
                message: "Invalid input data".to_string(),
                details: Some(serde_json::json!({"field": "username"})),
            },
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: "req-123456".to_string(),
        };

        // Test serialization
        let serialized = serde_json::to_string(&error_response).unwrap();
        let deserialized: ErrorResponse = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.error.code, error_response.error.code);
        assert_eq!(deserialized.error.message, error_response.error.message);
    }

    #[test]
    fn test_health_response_validation() {
        let health_response = HealthResponse {
            status: "healthy".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            version: "0.1.0".to_string(),
        };

        // Test serialization
        let serialized = serde_json::to_string(&health_response).unwrap();
        let deserialized: HealthResponse = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.status, health_response.status);
        assert_eq!(deserialized.version, health_response.version);
    }

    #[test]
    fn test_invalid_json_deserialization() {
        // Test invalid JSON for registration start request
        let invalid_json = r#"{"username": "test@example.com"}"#; // Missing display_name
        
        let result: Result<RegistrationStartRequest, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());

        // Test invalid JSON for authentication start request
        let invalid_auth_json = r#"{"username": 123}"#; // username should be string
        
        let result: Result<AuthenticationStartRequest, _> = serde_json::from_str(invalid_auth_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_edge_cases() {
        // Test empty strings
        let empty_request = RegistrationStartRequest {
            username: "".to_string(),
            display_name: "".to_string(),
            attestation: None,
            authenticator_selection: None,
        };

        let serialized = serde_json::to_string(&empty_request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, "");
        assert_eq!(deserialized.display_name, "");

        // Test very long strings
        let long_string = "a".repeat(1000);
        let long_request = RegistrationStartRequest {
            username: format!("{}@example.com", long_string),
            display_name: long_string.clone(),
            attestation: Some(long_string.clone()),
            authenticator_selection: None,
        };

        let serialized = serde_json::to_string(&long_request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, long_request.username);
        assert_eq!(deserialized.display_name, long_request.display_name);
    }
}