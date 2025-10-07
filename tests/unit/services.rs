//! Service layer unit tests

use fido_server::services::webauthn::WebAuthnService;
use fido_server::services::challenge::{ChallengeService, InMemoryChallengeStore};
use fido_server::services::user::{UserService, InMemoryUserRepository};
use fido_server::services::credential::{CredentialService, InMemoryCredentialRepository};
use fido_server::schema::credential::Credential;
use fido_server::error::{AppError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_webauthn_service_creation() {
        let challenge_service = ChallengeService::new(InMemoryChallengeStore::new());
        let user_service = UserService::new(InMemoryUserRepository::new());
        let credential_service = CredentialService::new(InMemoryCredentialRepository::new());

        let webauthn_service = WebAuthnService::new(
            challenge_service,
            user_service,
            credential_service,
            "localhost".to_string(),
            "Test RP".to_string(),
            "https://localhost".to_string(),
        );

        // Service should be created successfully
        assert_eq!(webauthn_service.rp_id, "localhost");
        assert_eq!(webauthn_service.rp_name, "Test RP");
    }

    #[tokio::test]
    async fn test_challenge_generation() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = uuid::Uuid::new_v4();

        let challenge = service.create_registration_challenge(user_id).await.unwrap();
        
        // Challenge should have required properties
        assert!(!challenge.id.is_empty());
        assert!(!challenge.challenge_data.is_empty());
        assert_eq!(challenge.user_id, Some(user_id));
        assert!(!challenge.is_expired());
    }

    #[tokio::test]
    async fn test_credential_storage() {
        let repo = InMemoryCredentialRepository::new();
        let service = CredentialService::new(repo);
        let user_id = uuid::Uuid::new_v4();
        
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        // Should be able to register credential
        service.register_credential(credential.clone()).await.unwrap();
        
        // Should be able to retrieve credential
        let retrieved = service.get_credential(&credential.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, credential.id);
    }

    #[tokio::test]
    async fn test_user_service_creation() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        let user = service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(!user.id.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_challenge_validation() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = uuid::Uuid::new_v4();

        let challenge = service.create_registration_challenge(user_id).await.unwrap();
        
        // Valid challenge should validate
        let result = service.validate_challenge(&challenge.id, &challenge.challenge_data).await;
        assert!(result.is_ok());
        
        // Invalid challenge should fail
        let result = service.validate_challenge(&challenge.id, &[9, 9, 9, 9]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_credential_counter_regression() {
        let repo = InMemoryCredentialRepository::new();
        let service = CredentialService::new(repo);
        let user_id = uuid::Uuid::new_v4();
        
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        service.register_credential(credential.clone()).await.unwrap();
        
        // First authentication with counter 10
        service.authenticate_credential(&credential.id, 10).await.unwrap();
        
        // Try authentication with counter 5 (regression) - should fail
        let result = service.authenticate_credential(&credential.id, 5).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_user_validation() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Valid email should pass
        assert!(service.validate_username("test@example.com").is_ok());
        
        // Invalid email should fail
        assert!(service.validate_username("invalid-email").is_err());
        assert!(service.validate_username("").is_err());
        
        // Valid display name should pass
        assert!(service.validate_display_name("Test User").is_ok());
        
        // Invalid display name should fail
        assert!(service.validate_display_name("").is_err());
    }

    #[tokio::test]
    async fn test_credential_validation() {
        let user_id = uuid::Uuid::new_v4();
        
        // Valid credential should pass validation
        let valid_credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );
        assert!(valid_credential.validate().is_ok());
        
        // Invalid credential (empty ID) should fail
        let invalid_credential = Credential::new(
            vec![],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );
        assert!(invalid_credential.validate().is_err());
        
        // Invalid credential (invalid attestation format) should fail
        let invalid_credential2 = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "invalid-format".to_string(),
            vec!["usb".to_string()],
        );
        assert!(invalid_credential2.validate().is_err());
    }
}