//! Unit tests for WebAuthn service

use crate::error::AppError;
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialGetOptionsRequest,
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference,
    RegistrationCompletionRequest,
    AuthenticationCompletionRequest,
};
use crate::services::webauthn::InMemoryWebAuthnService;
use crate::services::WebAuthnService;
use serde_json::json;

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria::default()),
            attestation: Some(AttestationConveyancePreference::Direct),
        };

        let result = service.generate_registration_challenge(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
        assert_eq!(response.rp.name, "Example Corporation");
        assert_eq!(response.user.name, "test@example.com");
        assert_eq!(response.user.display_name, "Test User");
        assert!(!response.challenge.is_empty());
        assert!(response.challenge.len() >= 16);
        assert_eq!(response.pub_key_cred_params.len(), 1);
        assert_eq!(response.pub_key_cred_params[0].alg, -7);
        assert_eq!(response.pub_key_cred_params[0].cred_type, "public-key");
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_missing_username() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = service.generate_registration_challenge(request).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_missing_display_name() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = service.generate_registration_challenge(request).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_verify_registration_success() {
        let service = InMemoryWebAuthnService::new();
        
        let request = RegistrationCompletionRequest {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: json!({
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ"
            }),
            get_client_extension_results: Some(json!({})),
        };

        let result = service.verify_registration(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_generate_authentication_challenge_user_not_found() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialGetOptionsRequest {
            username: "nonexistent@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let result = service.generate_authentication_challenge(request).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_generate_authentication_challenge_missing_username() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialGetOptionsRequest {
            username: "".to_string(),
            user_verification: None,
        };

        let result = service.generate_authentication_challenge(request).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_verify_authentication_success() {
        let service = InMemoryWebAuthnService::new();
        
        let request = AuthenticationCompletionRequest {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: json!({
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=",
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEUCIQDpo2qM4TF8Fc8z1LXf5I4QqvLp5oKjZl5XG_wR1A",
                "userHandle": ""
            }),
            get_client_extension_results: Some(json!({})),
        };

        let result = service.verify_authentication(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_challenge_generation_entropy() {
        let service = InMemoryWebAuthnService::new();
        
        // Generate multiple challenges and verify they're unique
        let mut challenges = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let challenge = service.generate_challenge_string();
            assert!(!challenge.is_empty());
            assert!(challenge.len() >= 16);
            challenges.insert(challenge);
        }
        
        // All challenges should be unique
        assert_eq!(challenges.len(), 100);
    }

    #[tokio::test]
    async fn test_challenge_storage_and_cleanup() {
        let service = InMemoryWebAuthnService::new();
        
        let challenge = service.generate_challenge_string();
        let username = Some("test@example.com".to_string());
        
        let challenge_id = service.store_challenge(challenge.clone(), username.clone()).await;
        
        // Verify challenge is stored
        let challenges = service.challenges.read().await;
        let stored_challenge = challenges.get(&challenge_id).unwrap();
        assert_eq!(stored_challenge.challenge, challenge);
        assert_eq!(stored_challenge.username, username);
        
        drop(challenges);
        
        // Cleanup expired challenges (should not remove the newly created one)
        service.cleanup_expired_challenges().await;
        
        let challenges = service.challenges.read().await;
        assert!(challenges.contains_key(&challenge_id));
    }
}