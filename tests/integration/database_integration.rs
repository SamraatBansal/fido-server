//! Database integration tests

#[cfg(test)]
mod tests {
    use fido_server::services::user::{UserService, InMemoryUserRepository};
    use fido_server::services::credential::{CredentialService, InMemoryCredentialRepository};
    use fido_server::services::challenge::{ChallengeService, InMemoryChallengeStore};
    
    use fido_server::schema::credential::Credential;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_user_service_integration() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);
        
        // Create user
        let user = service.create_user(
            "integration-test@example.com".to_string(),
            "Integration Test User".to_string(),
        ).await.unwrap();
        
        // Retrieve user
        let retrieved = service.get_user_by_username("integration-test@example.com").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, user.id);
        
        // Update user
        let mut updated_user = user.clone();
        updated_user.display_name = "Updated Name".to_string();
        service.update_user(updated_user).await.unwrap();
        
        let updated_retrieved = service.get_user(&user.id).await.unwrap();
        assert!(updated_retrieved.is_some());
        assert_eq!(updated_retrieved.unwrap().display_name, "Updated Name");
    }

    #[tokio::test]
    async fn test_credential_service_integration() {
        let repo = InMemoryCredentialRepository::new();
        let service = CredentialService::new(repo);
        let user_id = Uuid::new_v4();
        
        // Create credential
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );
        
        service.register_credential(credential.clone()).await.unwrap();
        
        // Retrieve credential
        let retrieved = service.get_credential(&credential.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, credential.id);
        
        // Get user credentials
        let user_creds = service.get_user_credentials(&user_id).await.unwrap();
        assert_eq!(user_creds.len(), 1);
        assert_eq!(user_creds[0].id, credential.id);
    }

    #[tokio::test]
    async fn test_challenge_service_integration() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = Uuid::new_v4();
        
        // Create registration challenge
        let reg_challenge = service.create_registration_challenge(user_id).await.unwrap();
        assert!(!reg_challenge.id.is_empty());
        assert!(!reg_challenge.challenge_data.is_empty());
        
        // Create authentication challenge
        let auth_challenge = service.create_authentication_challenge(user_id).await.unwrap();
        assert!(!auth_challenge.id.is_empty());
        assert!(!auth_challenge.challenge_data.is_empty());
        
        // Validate challenge
        let validation_result = service.validate_challenge(&reg_challenge.id, &reg_challenge.challenge_data).await;
        assert!(validation_result.is_ok());
        
        // Challenge should be consumed
        let retrieved = service.get_challenge(&reg_challenge.id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_full_service_integration() {
        let user_repo = InMemoryUserRepository::new();
        let user_service = UserService::new(user_repo);
        
        let cred_repo = InMemoryCredentialRepository::new();
        let cred_service = CredentialService::new(cred_repo);
        
        let challenge_store = InMemoryChallengeStore::new();
        let challenge_service = ChallengeService::new(challenge_store);
        
        // Create user
        let user = user_service.create_user(
            "full-integration@example.com".to_string(),
            "Full Integration User".to_string(),
        ).await.unwrap();
        
        // Create challenge
        let challenge = challenge_service.create_registration_challenge(user.id).await.unwrap();
        
        // Create credential
        let credential = Credential::new(
            vec![10, 20, 30, 40],
            user.id,
            vec![50, 60, 70, 80],
            "fido-u2f".to_string(),
            vec!["nfc".to_string()],
        );
        
        cred_service.register_credential(credential).await.unwrap();
        
        // Validate challenge
        challenge_service.validate_challenge(&challenge.id, &challenge.challenge_data).await.unwrap();
        
        // Verify all data is consistent
        let final_user = user_service.get_user(&user.id).await.unwrap();
        assert!(final_user.is_some());
        
        let final_creds = cred_service.get_user_credentials(&user.id).await.unwrap();
        assert_eq!(final_creds.len(), 1);
    }
}