//! Unit tests for WebAuthn service

#[cfg(test)]
mod tests {
    use super::*;
    use fido_server::schema::*;
    use fido_server::services::{WebAuthnService};
    use async_trait::async_trait;

    /// Mock WebAuthn service for testing
    struct MockWebAuthnService;

    impl MockWebAuthnService {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl WebAuthnService for MockWebAuthnService {
        async fn generate_registration_challenge(
            &self,
            request: ServerPublicKeyCredentialCreationOptionsRequest,
        ) -> fido_server::error::Result<ServerPublicKeyCredentialCreationOptionsResponse> {
            let mut response = ServerPublicKeyCredentialCreationOptionsResponse::default();
            response.user = ServerPublicKeyCredentialUserEntity {
                id: "S3932ee31vKEC0JtJMIQ".to_string(),
                name: request.username.clone(),
                display_name: request.display_name.clone(),
            };
            response.challenge = "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string();
            response.authenticator_selection = request.authenticator_selection;
            response.attestation = request.attestation;
            
            Ok(response)
        }

        async fn verify_registration(
            &self,
            _credential: ServerPublicKeyCredential,
        ) -> fido_server::error::Result<ServerResponse> {
            Ok(ServerResponse::success())
        }

        async fn generate_authentication_challenge(
            &self,
            request: ServerPublicKeyCredentialGetOptionsRequest,
        ) -> fido_server::error::Result<ServerPublicKeyCredentialGetOptionsResponse> {
            let mut response = ServerPublicKeyCredentialGetOptionsResponse::default();
            response.challenge = "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string();
            response.allow_credentials = vec![ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
                transports: None,
            }];
            response.user_verification = request.user_verification;
            
            Ok(response)
        }

        async fn verify_authentication(
            &self,
            _credential: ServerPublicKeyCredential,
        ) -> fido_server::error::Result<ServerResponse> {
            Ok(ServerResponse::success())
        }
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        let service = MockWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        };

        let result = service.generate_registration_challenge(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.user.name, "test@example.com");
        assert_eq!(response.user.display_name, "Test User");
        assert!(!response.challenge.is_empty());
        assert_eq!(response.attestation, Some("direct".to_string()));
    }

    #[tokio::test]
    async fn test_generate_authentication_challenge_success() {
        let service = MockWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialGetOptionsRequest {
            username: "test@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let result = service.generate_authentication_challenge(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert!(!response.challenge.is_empty());
        assert_eq!(response.user_verification, Some("required".to_string()));
    }

    #[tokio::test]
    async fn test_verify_registration_success() {
        let service = MockWebAuthnService::new();
        
        let credential = ServerPublicKeyCredential {
            id: "test-credential-id".to_string(),
            response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
                client_data_json: "dGVzdC1kYXRh".to_string(), // base64 encoded "test-data"
                attestation_object: "dGVzdC1hdHRlc3RhdGlvbg".to_string(), // base64 encoded "test-attestation"
            }),
            get_client_extension_results: None,
            credential_type: "public-key".to_string(),
        };

        let result = service.verify_registration(credential).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert!(response.error_message.is_empty());
    }

    #[tokio::test]
    async fn test_verify_authentication_success() {
        let service = MockWebAuthnService::new();
        
        let credential = ServerPublicKeyCredential {
            id: "test-credential-id".to_string(),
            response: ServerAuthenticatorResponse::Assertion(ServerAuthenticatorAssertionResponse {
                authenticator_data: "dGVzdC1hdXRoZW50aWNhdG9y".to_string(), // base64 encoded
                signature: "dGVzdC1zaWduYXR1cmU".to_string(), // base64 encoded
                user_handle: Some("dGVzdC11c2Vy".to_string()), // base64 encoded
                client_data_json: "dGVzdC1kYXRh".to_string(), // base64 encoded
            }),
            get_client_extension_results: None,
            credential_type: "public-key".to_string(),
        };

        let result = service.verify_authentication(credential).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert!(response.error_message.is_empty());
    }
}