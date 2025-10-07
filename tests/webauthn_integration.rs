//! WebAuthn Integration Tests

use fido_server::services::webauthn::WebAuthnService;
use fido_server::services::challenge::{ChallengeService, InMemoryChallengeStore};
use fido_server::services::user::{UserService, InMemoryUserRepository};
use fido_server::services::credential::{CredentialService, InMemoryCredentialRepository};
use fido_server::schema::credential::Credential;

#[tokio::test]
async fn test_start_registration_success() {
    // Test the actual WebAuthn service registration start
    
    // Arrange
    let challenge_service = fido_server::services::challenge::ChallengeService::new(InMemoryChallengeStore::new());
    let user_service = fido_server::services::user::UserService::new(InMemoryUserRepository::new());
    let credential_service = fido_server::services::credential::CredentialService::new(InMemoryCredentialRepository::new());
    
    let webauthn_service = WebAuthnService::new(
        challenge_service,
        user_service,
        credential_service,
        "localhost".to_string(),
        "Test RP".to_string(),
        "https://localhost".to_string(),
    );
    
    // Act
    let result = webauthn_service.start_registration(
        "test@example.com".to_string(),
        "Test User".to_string(),
    ).await;
    
    // Assert
    assert!(result.is_ok(), "Registration start should succeed");
    
    let response = result.unwrap();
    assert!(response.get("challengeId").is_some());
    assert!(response.get("credentialCreationOptions").is_some());
}

#[tokio::test]
async fn test_start_registration_invalid_user() {
    // Test the actual WebAuthn service with invalid user data
    
    // Arrange
    let challenge_service = fido_server::services::challenge::ChallengeService::new(InMemoryChallengeStore::new());
    let user_service = fido_server::services::user::UserService::new(InMemoryUserRepository::new());
    let credential_service = fido_server::services::credential::CredentialService::new(InMemoryCredentialRepository::new());
    
    let webauthn_service = WebAuthnService::new(
        challenge_service,
        user_service,
        credential_service,
        "localhost".to_string(),
        "Test RP".to_string(),
        "https://localhost".to_string(),
    );
    
    // Act
    let result = webauthn_service.start_registration(
        "invalid-email".to_string(),  // Invalid email
        "Test User".to_string(),
    ).await;
    
    // Assert
    assert!(result.is_err(), "Registration start should fail with invalid email");
}

#[tokio::test]
async fn test_start_authentication_success() {
    // Test the actual WebAuthn service authentication start
    
    // Arrange
    let challenge_service = fido_server::services::challenge::ChallengeService::new(InMemoryChallengeStore::new());
    let user_service = fido_server::services::user::UserService::new(InMemoryUserRepository::new());
    let credential_service = fido_server::services::credential::CredentialService::new(InMemoryCredentialRepository::new());
    
    let webauthn_service = WebAuthnService::new(
        challenge_service,
        user_service,
        credential_service,
        "localhost".to_string(),
        "Test RP".to_string(),
        "https://localhost".to_string(),
    );
    
    // First create a user and credential
    let user = webauthn_service.user_service.create_user(
        "test@example.com".to_string(),
        "Test User".to_string(),
    ).await.unwrap();
    
    let credential = Credential::new(
        vec![1, 2, 3, 4],
        user.id,
        vec![5, 6, 7, 8],
        "none".to_string(),
        vec!["internal".to_string()],
    );
    webauthn_service.credential_service.register_credential(credential).await.unwrap();
    
    // Act
    let result = webauthn_service.start_authentication(
        "test@example.com".to_string(),
    ).await;
    
    // Assert
    assert!(result.is_ok(), "Authentication start should succeed");
    
    let response = result.unwrap();
    assert!(response.get("challengeId").is_some());
    assert!(response.get("credentialRequestOptions").is_some());
}

#[tokio::test]
async fn test_start_authentication_user_not_found() {
    // Test the actual WebAuthn service with non-existent user
    
    // Arrange
    let challenge_service = fido_server::services::challenge::ChallengeService::new(InMemoryChallengeStore::new());
    let user_service = fido_server::services::user::UserService::new(InMemoryUserRepository::new());
    let credential_service = fido_server::services::credential::CredentialService::new(InMemoryCredentialRepository::new());
    
    let webauthn_service = WebAuthnService::new(
        challenge_service,
        user_service,
        credential_service,
        "localhost".to_string(),
        "Test RP".to_string(),
        "https://localhost".to_string(),
    );
    
    // Act
    let result = webauthn_service.start_authentication(
        "nonexistent@example.com".to_string(),
    ).await;
    
    // Assert
    assert!(result.is_err(), "Authentication start should fail for non-existent user");
}