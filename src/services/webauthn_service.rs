//! Unit tests for WebAuthn service

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::*;

    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let request = create_test_registration_request();
        let result = service.generate_registration_challenge(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.rp.name, "Test RP");
        assert_eq!(response.user.name, "johndoe@example.com");
        assert_eq!(response.user.display_name, "John Doe");
        assert!(!response.challenge.is_empty());
        assert!(!response.pub_key_cred_params.is_empty());
        assert!(response.timeout.is_some());
        assert_eq!(response.attestation, Some("direct".to_string()));
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_minimal() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = service.generate_registration_challenge(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.user.name, "test@example.com");
        assert_eq!(response.user.display_name, "Test User");
        assert_eq!(response.attestation, Some("none".to_string()));
    }

    #[tokio::test]
    async fn test_verify_registration_attestation_success() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let credential = create_mock_attestation_credential();
        let result = service.verify_registration_attestation(credential).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_verify_registration_attestation_missing_id() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let mut credential = create_mock_attestation_credential();
        credential.id = "".to_string();

        let result = service.verify_registration_attestation(credential).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::BadRequest(msg) => {
                assert!(msg.contains("Missing credential ID"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn test_verify_registration_attestation_missing_data() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let mut credential = create_mock_attestation_credential();
        match &mut credential.response {
            ServerAuthenticatorResponse::Attestation(attestation) => {
                attestation.client_data_json = "".to_string();
            }
            _ => panic!("Expected attestation response"),
        }

        let result = service.verify_registration_attestation(credential).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::BadRequest(msg) => {
                assert!(msg.contains("Missing attestation data"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn test_generate_authentication_challenge_success() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let request = create_test_authentication_request();
        let result = service.generate_authentication_challenge(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.rp_id, "localhost");
        assert!(!response.challenge.is_empty());
        assert!(response.timeout.is_some());
        assert_eq!(response.user_verification, Some("required".to_string()));
    }

    #[tokio::test]
    async fn test_verify_authentication_assertion_success() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let credential = create_mock_assertion_credential();
        let result = service.verify_authentication_assertion(credential).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_verify_authentication_assertion_missing_id() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let mut credential = create_mock_assertion_credential();
        credential.id = "".to_string();

        let result = service.verify_authentication_assertion(credential).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::BadRequest(msg) => {
                assert!(msg.contains("Missing credential ID"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn test_verify_authentication_assertion_missing_data() {
        let service = WebAuthnService::new(
            "Test RP".to_string(),
            "localhost".to_string(),
            "http://localhost:8080".to_string(),
        );

        let mut credential = create_mock_assertion_credential();
        match &mut credential.response {
            ServerAuthenticatorResponse::Assertion(assertion) => {
                assertion.authenticator_data = "".to_string();
            }
            _ => panic!("Expected assertion response"),
        }

        let result = service.verify_authentication_assertion(credential).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::BadRequest(msg) => {
                assert!(msg.contains("Missing assertion data"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }
}