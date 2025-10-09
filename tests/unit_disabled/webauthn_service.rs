//! Unit tests for WebAuthn service

use fido2_webauthn_server::services::WebAuthnService;
use fido2_webauthn_server::schema::*;

#[cfg(test)]
mod webauthn_service_tests {
    use super::*;

    #[test]
    fn test_webauthn_service_creation() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080");
        assert!(service.is_ok(), "WebAuthn service should be created successfully");
        
        let service = service.unwrap();
        // Test that service was created (we can't access private fields directly)
        // but we can test that it works by calling methods
    }

    #[test]
    fn test_webauthn_service_creation_with_invalid_origin() {
        // Even with invalid origin, service creation should succeed
        // (validation happens during operations)
        let service = WebAuthnService::new("localhost", "Test RP", "invalid-origin");
        assert!(service.is_ok(), "WebAuthn service should be created even with invalid origin");
    }

    #[tokio::test]
    async fn test_generate_registration_challenge() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let result = service.generate_registration_challenge(
            "testuser@example.com",
            "Test User"
        ).await;

        assert!(result.is_ok(), "Registration challenge generation should succeed");
        
        let challenge_response = result.unwrap();
        assert_eq!(challenge_response.status, "ok");
        assert_eq!(challenge_response.error_message, "");
        assert!(!challenge_response.challenge.is_empty(), "Challenge should not be empty");
        assert_eq!(challenge_response.rp.name, "Test RP");
        assert_eq!(challenge_response.user.name, "testuser@example.com");
        assert_eq!(challenge_response.user.display_name, "Test User");
        assert!(!challenge_response.pub_key_cred_params.is_empty(), "Should have credential parameters");
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_different_users() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let result1 = service.generate_registration_challenge(
            "user1@example.com",
            "User One"
        ).await;

        let result2 = service.generate_registration_challenge(
            "user2@example.com",
            "User Two"
        ).await;

        assert!(result1.is_ok(), "First challenge generation should succeed");
        assert!(result2.is_ok(), "Second challenge generation should succeed");

        let challenge1 = result1.unwrap();
        let challenge2 = result2.unwrap();

        // Challenges should be different
        assert_ne!(challenge1.challenge, challenge2.challenge, "Challenges should be unique");
        
        // User info should be different
        assert_ne!(challenge1.user.name, challenge2.user.name);
        assert_ne!(challenge1.user.display_name, challenge2.user.display_name);
    }

    #[tokio::test]
    async fn test_generate_authentication_challenge() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let result = service.generate_authentication_challenge("testuser@example.com").await;

        assert!(result.is_ok(), "Authentication challenge generation should succeed");
        
        let challenge_response = result.unwrap();
        assert_eq!(challenge_response.status, "ok");
        assert_eq!(challenge_response.error_message, "");
        assert!(!challenge_response.challenge.is_empty(), "Challenge should not be empty");
        assert_eq!(challenge_response.rp_id, "localhost");
        assert_eq!(challenge_response.user_verification, Some("required".to_string()));
    }

    #[tokio::test]
    async fn test_verify_registration_attestation() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let attestation = crate::fixtures::AttestationResponseFactory::valid();
        let result = service.verify_registration(&attestation, "mock_challenge_id").await;

        assert!(result.is_ok(), "Attestation verification should succeed (mock implementation)");
        
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_verify_authentication_assertion() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let assertion = crate::fixtures::AssertionResponseFactory::valid();
        let result = service.verify_authentication(&assertion, "mock_challenge_id").await;

        assert!(result.is_ok(), "Assertion verification should succeed (mock implementation)");
        
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_challenge_format_validation() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let result = service.generate_registration_challenge(
            "testuser@example.com",
            "Test User"
        ).await;

        assert!(result.is_ok(), "Challenge generation should succeed");
        
        let challenge_response = result.unwrap();
        let challenge = &challenge_response.challenge;

        // Challenge should be valid base64url
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge).is_ok(),
                "Challenge should be valid base64url");

        // Challenge should be reasonable length (16+ bytes when decoded)
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge).unwrap();
        assert!(decoded.len() >= 16, "Challenge should be at least 16 bytes when decoded");
    }

    #[tokio::test]
    async fn test_user_id_generation() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let result = service.generate_registration_challenge(
            "testuser@example.com",
            "Test User"
        ).await;

        assert!(result.is_ok(), "Challenge generation should succeed");
        
        let challenge_response = result.unwrap();
        let user_id = &challenge_response.user.id;

        // User ID should be valid base64url
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(user_id).is_ok(),
                "User ID should be valid base64url");

        // User ID should be reasonable length (16 bytes when decoded for UUID)
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(user_id).unwrap();
        assert_eq!(decoded.len(), 16, "User ID should be 16 bytes when decoded (UUID)");
    }

    #[tokio::test]
    async fn test_credential_parameters() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let result = service.generate_registration_challenge(
            "testuser@example.com",
            "Test User"
        ).await;

        assert!(result.is_ok(), "Challenge generation should succeed");
        
        let challenge_response = result.unwrap();
        let params = &challenge_response.pub_key_cred_params;

        assert!(!params.is_empty(), "Should have at least one credential parameter");
        
        // Should include ES256 (-7)
        let has_es256 = params.iter().any(|p| p.alg == -7 && p.cred_type == "public-key");
        assert!(has_es256, "Should include ES256 algorithm");
    }

    #[tokio::test]
    async fn test_timeout_configuration() {
        let service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");

        let reg_result = service.generate_registration_challenge(
            "testuser@example.com",
            "Test User"
        ).await;

        let auth_result = service.generate_authentication_challenge("testuser@example.com").await;

        assert!(reg_result.is_ok(), "Registration challenge generation should succeed");
        assert!(auth_result.is_ok(), "Authentication challenge generation should succeed");

        let reg_response = reg_result.unwrap();
        let auth_response = auth_result.unwrap();

        assert_eq!(reg_response.timeout, Some(60000), "Registration timeout should be 60000ms");
        assert_eq!(auth_response.timeout, Some(60000), "Authentication timeout should be 60000ms");
    }
}