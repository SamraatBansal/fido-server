//! Unit tests for WebAuthn functionality

use fido_server::webauthn::*;
use fido_server::webauthn::memory_store::*;
use fido_server::webauthn::service::*;
use chrono::Utc;
use uuid::Uuid;

#[tokio::test]
async fn test_challenge_generation() {
    let config = WebAuthnConfig::default();
    let challenge_store = InMemoryChallengeStore::new();
    let user_repo = InMemoryUserRepository::new();
    let credential_repo = InMemoryCredentialRepository::new();
    
    let service = WebAuthnServiceImpl::new(config, challenge_store, user_repo, credential_repo).unwrap();
    
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
        extensions: None,
    };
    
    let response = service.begin_registration(request).await.unwrap();
    
    // Verify challenge is generated and properly formatted
    assert!(!response.challenge.is_empty());
    assert_eq!(response.status, "ok");
    assert_eq!(response.rp.name, "FIDO Server");
    assert_eq!(response.user.name, "test@example.com");
    assert_eq!(response.user.display_name, "Test User");
}

#[tokio::test]
async fn test_registration_with_invalid_username() {
    let config = WebAuthnConfig::default();
    let challenge_store = InMemoryChallengeStore::new();
    let user_repo = InMemoryUserRepository::new();
    let credential_repo = InMemoryCredentialRepository::new();
    
    let service = WebAuthnServiceImpl::new(config, challenge_store, user_repo, credential_repo).unwrap();
    
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "".to_string(), // Empty username
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
        extensions: None,
    };
    
    let result = service.begin_registration(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_authentication_user_not_found() {
    let config = WebAuthnConfig::default();
    let challenge_store = InMemoryChallengeStore::new();
    let user_repo = InMemoryUserRepository::new();
    let credential_repo = InMemoryCredentialRepository::new();
    
    let service = WebAuthnServiceImpl::new(config, challenge_store, user_repo, credential_repo).unwrap();
    
    let request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "nonexistent@example.com".to_string(),
        user_verification: None,
        extensions: None,
    };
    
    let result = service.begin_authentication(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_challenge_store_operations() {
    let store = InMemoryChallengeStore::new();
    
    // Store a challenge
    let challenge = "test_challenge_123";
    let username = "test@example.com";
    let expires_at = Utc::now() + chrono::Duration::minutes(5);
    
    store.store_challenge(challenge, username, expires_at).await.unwrap();
    
    // Validate and consume the challenge
    let is_valid = store.validate_and_consume_challenge(challenge, username).await.unwrap();
    assert!(is_valid);
    
    // Second attempt should fail
    let is_valid_again = store.validate_and_consume_challenge(challenge, username).await.unwrap();
    assert!(!is_valid_again);
}

#[tokio::test]
async fn test_challenge_expiration() {
    let store = InMemoryChallengeStore::new();
    
    // Store an expired challenge
    let challenge = "expired_challenge";
    let username = "test@example.com";
    let expires_at = Utc::now() - chrono::Duration::minutes(1); // Already expired
    
    store.store_challenge(challenge, username, expires_at).await.unwrap();
    
    // Should fail due to expiration
    let is_valid = store.validate_and_consume_challenge(challenge, username).await.unwrap();
    assert!(!is_valid);
}

#[tokio::test]
async fn test_user_repository_operations() {
    let repo = InMemoryUserRepository::new();
    
    // Create a user
    let new_user = NewUser {
        id: Uuid::new_v4().to_string(),
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        created_at: Utc::now(),
    };
    
    let created_user = repo.create_user(new_user.clone()).await.unwrap();
    assert_eq!(created_user.username, new_user.username);
    assert_eq!(created_user.display_name, new_user.display_name);
    
    // Get user by username
    let found_user = repo.get_user_by_username(&new_user.username).await.unwrap();
    assert!(found_user.is_some());
    assert_eq!(found_user.unwrap().username, new_user.username);
    
    // Try to create duplicate user
    let duplicate_user = NewUser {
        id: Uuid::new_v4().to_string(),
        username: new_user.username.clone(), // Same username
        display_name: "Another User".to_string(),
        created_at: Utc::now(),
    };
    
    let result = repo.create_user(duplicate_user).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_credential_repository_operations() {
    let repo = InMemoryCredentialRepository::new();
    
    // Create a credential
    let new_credential = NewCredential {
        id: Uuid::new_v4().to_string(),
        user_id: "user123".to_string(),
        public_key: vec![1, 2, 3, 4],
        sign_count: 0,
        created_at: Utc::now(),
        attestation_format: "none".to_string(),
        aaguid: None,
    };
    
    let created_credential = repo.store_credential(new_credential.clone()).await.unwrap();
    assert_eq!(created_credential.id, new_credential.id);
    assert_eq!(created_credential.user_id, new_credential.user_id);
    
    // Get credential by ID
    let found_credential = repo.get_credential_by_id(&new_credential.id).await.unwrap();
    assert!(found_credential.is_some());
    assert_eq!(found_credential.unwrap().id, new_credential.id);
    
    // Get credentials by user
    let user_credentials = repo.get_credentials_by_user(&new_credential.user_id).await.unwrap();
    assert_eq!(user_credentials.len(), 1);
    assert_eq!(user_credentials[0].id, new_credential.id);
    
    // Update sign count
    repo.update_sign_count(&new_credential.id, 5).await.unwrap();
    let updated_credential = repo.get_credential_by_id(&new_credential.id).await.unwrap().unwrap();
    assert_eq!(updated_credential.sign_count, 5);
}

#[tokio::test]
async fn test_server_response_creation() {
    // Test success response
    let success = ServerResponse::success();
    assert_eq!(success.status, "ok");
    assert_eq!(success.error_message, "");
    
    // Test error response
    let error = ServerResponse::error("Something went wrong");
    assert_eq!(error.status, "failed");
    assert_eq!(error.error_message, "Something went wrong");
}

#[tokio::test]
async fn test_webauthn_config_validation() {
    // Valid config
    let valid_config = WebAuthnConfig::new("Test RP", "example.com", "https://example.com");
    assert!(valid_config.validate().is_ok());
    
    // Invalid config (empty RP name)
    let mut invalid_config = WebAuthnConfig::default();
    invalid_config.rp_name = "".to_string();
    assert!(invalid_config.validate().is_err());
    
    // Invalid config (empty RP ID)
    let mut invalid_config = WebAuthnConfig::default();
    invalid_config.rp_id = "".to_string();
    assert!(invalid_config.validate().is_err());
    
    // Invalid config (zero timeout)
    let mut invalid_config = WebAuthnConfig::default();
    invalid_config.timeout = 0;
    assert!(invalid_config.validate().is_err());
}

#[tokio::test]
async fn test_registration_flow_with_existing_user() {
    let config = WebAuthnConfig::default();
    let challenge_store = InMemoryChallengeStore::new();
    let user_repo = InMemoryUserRepository::new();
    let credential_repo = InMemoryCredentialRepository::new();
    
    let service = WebAuthnServiceImpl::new(config, challenge_store, user_repo.clone(), credential_repo.clone()).unwrap();
    
    // First, create a user with existing credentials
    let user_id = Uuid::new_v4().to_string();
    let new_user = NewUser {
        id: user_id.clone(),
        username: "existing@example.com".to_string(),
        display_name: "Existing User".to_string(),
        created_at: Utc::now(),
    };
    user_repo.create_user(new_user).await.unwrap();
    
    // Add an existing credential
    let existing_credential = NewCredential {
        id: "existing_credential_123".to_string(),
        user_id: user_id.clone(),
        public_key: vec![1, 2, 3, 4],
        sign_count: 0,
        created_at: Utc::now(),
        attestation_format: "none".to_string(),
        aaguid: None,
    };
    credential_repo.store_credential(existing_credential).await.unwrap();
    
    // Now begin registration - should exclude existing credentials
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "existing@example.com".to_string(),
        display_name: "Existing User".to_string(),
        authenticator_selection: None,
        attestation: None,
        extensions: None,
    };
    
    let response = service.begin_registration(request).await.unwrap();
    
    // Verify that existing credentials are excluded
    assert!(response.exclude_credentials.is_some());
    let exclude_credentials = response.exclude_credentials.unwrap();
    assert_eq!(exclude_credentials.len(), 1);
    assert_eq!(exclude_credentials[0].id, "existing_credential_123");
}