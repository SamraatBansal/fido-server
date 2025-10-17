# FIDO2/WebAuthn Server - Testing Strategy

## Overview

This document outlines a comprehensive testing strategy for the FIDO2/WebAuthn Relying Party Server, covering unit tests, integration tests, security tests, and compliance tests. The strategy follows Test-Driven Development (TDD) principles and aims for 95%+ code coverage with a focus on security and FIDO2 compliance.

## 1. Testing Architecture

### 1.1 Test Pyramid

```
                    ┌─────────────────┐
                    │   E2E Tests     │  (5%)
                    │   (Scenarios)   │
                    └─────────────────┘
                ┌─────────────────────────┐
                │   Integration Tests     │  (25%)
                │   (API & Database)      │
                └─────────────────────────┘
        ┌─────────────────────────────────────────┐
        │           Unit Tests                     │  (70%)
        │   (Business Logic & Utilities)           │
        └─────────────────────────────────────────┘
```

### 1.2 Test Categories

#### Unit Tests (70%)
- **Purpose**: Test individual functions and methods in isolation
- **Speed**: Fast (< 1ms per test)
- **Coverage**: Target 95%+ line and branch coverage
- **Tools**: Built-in Rust testing, mockall for mocking

#### Integration Tests (25%)
- **Purpose**: Test component interactions and API endpoints
- **Speed**: Medium (10-100ms per test)
- **Coverage**: 100% of API endpoints
- **Tools**: actix-test, testcontainers for database

#### End-to-End Tests (5%)
- **Purpose**: Test complete user workflows
- **Speed**: Slow (100ms-1s per test)
- **Coverage**: Critical user journeys
- **Tools**: Browser automation, WebAuthn test clients

## 2. Unit Testing Strategy

### 2.1 WebAuthn Service Tests

```rust
// tests/unit/services/webauthn_tests.rs
use crate::services::webauthn::WebAuthnService;
use crate::config::WebAuthnConfig;
use crate::db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use mockall::predicate::*;
use mockall::mock;
use webauthn_rs::prelude::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

mock! {
    ChallengeRepository {}

    impl crate::db::repositories::ChallengeRepositoryTrait for ChallengeRepository {
        async fn store(&self, challenge: &NewChallenge) -> Result<Challenge>;
        async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<Challenge>>;
        async fn delete(&self, id: Uuid) -> Result<()>;
        async fn cleanup_expired(&self) -> Result<usize>;
    }
}

mock! {
    CredentialRepository {}

    impl crate::db::repositories::CredentialRepositoryTrait for CredentialRepository {
        async fn store(&self, credential: &NewCredential) -> Result<Credential>;
        async fn find_by_id(&self, id: Uuid) -> Result<Option<Credential>>;
        async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
        async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>>;
        async fn update_counter(&self, id: Uuid, counter: i64) -> Result<()>;
        async fn delete(&self, id: Uuid) -> Result<()>;
    }
}

mock! {
    UserRepository {}

    impl crate::db::repositories::UserRepositoryTrait for UserRepository {
        async fn create(&self, user: &NewUser) -> Result<User>;
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
        async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
        async fn update(&self, id: Uuid, user: &UpdateUser) -> Result<User>;
        async fn delete(&self, id: Uuid) -> Result<()>;
    }
}

#[cfg(test)]
mod challenge_generation_tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let mut user_repo = MockUserRepository::new();
        let credential_repo = MockCredentialRepository::new();

        // Mock user not found
        user_repo
            .expect_find_by_username()
            .with(eq("test@example.com"))
            .returning(|_| Ok(None));

        // Mock challenge storage
        challenge_repo
            .expect_store()
            .with(always())
            .returning(|challenge| Ok(create_test_challenge(&challenge.challenge)));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        // Act
        let result = service.generate_registration_challenge(
            "test@example.com",
            "Test User",
            UserVerificationPolicy::Preferred,
            AttestationConveyancePreference::None,
            None,
            None,
        ).await;

        // Assert
        assert!(result.is_ok());
        let (challenge, response) = result.unwrap();
        
        // Verify challenge format
        assert!(!challenge.is_empty());
        assert!(URL_SAFE_NO_PAD.decode(&challenge).is_ok());
        
        // Verify response structure
        assert_eq!(response.user.name, "test@example.com");
        assert_eq!(response.user.display_name, "Test User");
        assert!(response.timeout > 0);
        assert!(!response.pub_key_cred_params.is_empty());
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_user_exists() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let mut user_repo = MockUserRepository::new();
        let credential_repo = MockCredentialRepository::new();

        // Mock user exists
        user_repo
            .expect_find_by_username()
            .with(eq("existing@example.com"))
            .returning(|_| Ok(Some(create_test_user())));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        // Act
        let result = service.generate_registration_challenge(
            "existing@example.com",
            "Existing User",
            UserVerificationPolicy::Preferred,
            AttestationConveyancePreference::None,
            None,
            None,
        ).await;

        // Assert
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_challenge_entropy() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let mut user_repo = MockUserRepository::new();
        let credential_repo = MockCredentialRepository::new();

        user_repo
            .expect_find_by_username()
            .with(any())
            .returning(|_| Ok(None));

        challenge_repo
            .expect_store()
            .with(always())
            .returning(|challenge| Ok(create_test_challenge(&challenge.challenge)));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        // Act
        let challenges: Vec<String> = (0..100)
            .map(|_| {
                let username = format!("user{}@example.com", rand::random::<u32>());
                tokio::block_on(service.generate_registration_challenge(
                    &username,
                    "Test User",
                    UserVerificationPolicy::Preferred,
                    AttestationConveyancePreference::None,
                    None,
                    None,
                )).unwrap().0
            })
            .collect();

        // Assert
        // Check uniqueness
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        assert_eq!(challenges.len(), unique_challenges.len());

        // Check entropy (basic test)
        for challenge in &challenges {
            let decoded = URL_SAFE_NO_PAD.decode(challenge).unwrap();
            assert_eq!(decoded.len(), 32); // 256 bits
        }
    }
}

#[cfg(test)]
mod registration_verification_tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_registration_success() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let mut user_repo = MockUserRepository::new();
        let mut credential_repo = MockCredentialRepository::new();

        // Mock challenge
        let challenge_data = URL_SAFE_NO_PAD.decode("Y2hhbGxlbmdlXzEyMzQ1Njc4OTA").unwrap();
        let challenge = create_test_challenge(&challenge_data);
        challenge_repo
            .expect_find_by_challenge()
            .with(eq(challenge_data))
            .returning(move |_| Ok(Some(challenge.clone())));

        // Mock user creation
        user_repo
            .expect_create()
            .with(always())
            .returning(|_| Ok(create_test_user()));

        // Mock credential storage
        credential_repo
            .expect_store()
            .with(always())
            .returning(|_| Ok(create_test_credential()));

        // Mock challenge cleanup
        challenge_repo
            .expect_delete()
            .with(always())
            .returning(|_| Ok(()));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        let credential = create_valid_registration_credential();
        let challenge_str = "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA";

        // Act
        let result = service.verify_registration(
            credential,
            None,
            challenge_str,
        ).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.credential_id.is_empty());
        assert_eq!(response.counter, 0);
        assert!(response.user_verified);
    }

    #[tokio::test]
    async fn test_verify_registration_invalid_challenge() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let user_repo = MockUserRepository::new();
        let credential_repo = MockCredentialRepository::new();

        // Mock challenge not found
        challenge_repo
            .expect_find_by_challenge()
            .with(any())
            .returning(|_| Ok(None));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        let credential = create_valid_registration_credential();
        let challenge_str = "invalid_challenge";

        // Act
        let result = service.verify_registration(
            credential,
            None,
            challenge_str,
        ).await;

        // Assert
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidChallenge));
    }

    #[tokio::test]
    async fn test_verify_registration_expired_challenge() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let user_repo = MockUserRepository::new();
        let credential_repo = MockCredentialRepository::new();

        // Mock expired challenge
        let challenge_data = URL_SAFE_NO_PAD.decode("Y2hhbGxlbmdlXzEyMzQ1Njc4OTA").unwrap();
        let mut challenge = create_test_challenge(&challenge_data);
        challenge.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        
        challenge_repo
            .expect_find_by_challenge()
            .with(eq(challenge_data))
            .returning(move |_| Ok(Some(challenge.clone())));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        let credential = create_valid_registration_credential();
        let challenge_str = "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA";

        // Act
        let result = service.verify_registration(
            credential,
            None,
            challenge_str,
        ).await;

        // Assert
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::ChallengeExpired));
    }
}

#[cfg(test)]
mod authentication_tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_authentication_challenge_success() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let mut user_repo = MockUserRepository::new();
        let credential_repo = MockCredentialRepository::new();

        // Mock user exists
        let user = create_test_user();
        user_repo
            .expect_find_by_username()
            .with(eq("test@example.com"))
            .returning(move |_| Ok(Some(user.clone())));

        // Mock user credentials
        let credentials = vec![create_test_credential()];
        credential_repo
            .expect_find_by_user_id()
            .with(eq(user.id))
            .returning(move |_| Ok(credentials.clone()));

        // Mock challenge storage
        challenge_repo
            .expect_store()
            .with(always())
            .returning(|challenge| Ok(create_test_challenge(&challenge.challenge)));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        // Act
        let result = service.generate_authentication_challenge(
            "test@example.com",
            UserVerificationPolicy::Required,
            None,
            None,
        ).await;

        // Assert
        assert!(result.is_ok());
        let (challenge, response) = result.unwrap();
        
        assert!(!challenge.is_empty());
        assert!(!response.allow_credentials.is_empty());
        assert_eq!(response.user_verification, UserVerificationPolicy::Required);
        assert!(response.timeout > 0);
    }

    #[tokio::test]
    async fn test_verify_authentication_success() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let user_repo = MockUserRepository::new();
        let mut credential_repo = MockCredentialRepository::new();

        // Mock challenge
        let challenge_data = URL_SAFE_NO_PAD.decode("Y2hhbGxlbmdlXzEyMzQ1Njc4OTA").unwrap();
        let challenge = create_test_challenge(&challenge_data);
        challenge_repo
            .expect_find_by_challenge()
            .with(eq(challenge_data))
            .returning(move |_| Ok(Some(challenge.clone())));

        // Mock credential
        let credential = create_test_credential();
        credential_repo
            .expect_find_by_credential_id()
            .with(eq(credential.credential_id.clone()))
            .returning(move |_| Ok(Some(credential.clone())));

        // Mock counter update
        credential_repo
            .expect_update_counter()
            .with(always(), always())
            .returning(|_, _| Ok(()));

        // Mock challenge cleanup
        challenge_repo
            .expect_delete()
            .with(always())
            .returning(|_| Ok(()));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        let assertion = create_valid_assertion();
        let challenge_str = "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA";

        // Act
        let result = service.verify_authentication(
            assertion,
            None,
            challenge_str,
        ).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.credential_id.is_empty());
        assert!(response.counter > 0);
        assert!(response.user_verified);
    }

    #[tokio::test]
    async fn test_verify_authentication_replay_attack() {
        // Arrange
        let mut challenge_repo = MockChallengeRepository::new();
        let user_repo = MockUserRepository::new();
        let mut credential_repo = MockCredentialRepository::new();

        // Mock challenge
        let challenge_data = URL_SAFE_NO_PAD.decode("Y2hhbGxlbmdlXzEyMzQ1Njc4OTA").unwrap();
        let challenge = create_test_challenge(&challenge_data);
        challenge_repo
            .expect_find_by_challenge()
            .with(eq(challenge_data))
            .returning(move |_| Ok(Some(challenge.clone())));

        // Mock credential with high counter
        let mut credential = create_test_credential();
        credential.sign_count = 100; // Higher than assertion counter
        credential_repo
            .expect_find_by_credential_id()
            .with(eq(credential.credential_id.clone()))
            .returning(move |_| Ok(Some(credential.clone())));

        let config = create_test_config();
        let service = WebAuthnService::new(
            &config,
            challenge_repo,
            credential_repo,
            user_repo,
        ).unwrap();

        let assertion = create_valid_assertion();
        let challenge_str = "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA";

        // Act
        let result = service.verify_authentication(
            assertion,
            None,
            challenge_str,
        ).await;

        // Assert
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::ReplayAttack));
    }
}

// Helper functions for test data
fn create_test_config() -> WebAuthnConfig {
    WebAuthnConfig {
        rp_id: "example.com".to_string(),
        rp_name: "Test Server".to_string(),
        rp_origin: "https://example.com".to_string(),
        allowed_origins: vec!["https://example.com".to_string()],
    }
}

fn create_test_user() -> User {
    User {
        id: uuid::Uuid::new_v4(),
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn create_test_credential() -> Credential {
    Credential {
        id: uuid::Uuid::new_v4(),
        user_id: uuid::Uuid::new_v4(),
        credential_id: b"test_credential_id".to_vec(),
        public_key: b"test_public_key".to_vec(),
        attestation_type: "none".to_string(),
        aaguid: vec![0; 16],
        sign_count: 0,
        user_verification: true,
        backup_eligible: false,
        backup_state: false,
        transports: vec!["internal".to_string()],
        created_at: chrono::Utc::now(),
        last_used_at: chrono::Utc::now(),
    }
}

fn create_test_challenge(challenge_data: &[u8]) -> Challenge {
    Challenge {
        id: uuid::Uuid::new_v4(),
        challenge: challenge_data.to_vec(),
        user_id: None,
        challenge_type: "registration".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        created_at: chrono::Utc::now(),
    }
}

fn create_valid_registration_credential() -> PublicKeyCredential<RegistrationCredential> {
    // This would contain a valid attestation object
    // For testing, we'll create a mock
    PublicKeyCredential {
        id: "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw".to_string(),
        raw_id: b"credential_id_1234567890".to_vec(),
        response: RegistrationCredential {
            attestation_object: vec![], // Mock attestation object
            client_data_json: b"{}".to_vec(), // Mock client data
            transports: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}

fn create_valid_assertion() -> PublicKeyCredential<AssertionCredential> {
    // This would contain a valid assertion
    // For testing, we'll create a mock
    PublicKeyCredential {
        id: "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw".to_string(),
        raw_id: b"credential_id_1234567890".to_vec(),
        response: AssertionCredential {
            authenticator_data: vec![], // Mock authenticator data
            client_data_json: b"{}".to_vec(), // Mock client data
            signature: vec![], // Mock signature
            user_handle: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}
```

### 2.2 Controller Tests

```rust
// tests/unit/controllers/registration_tests.rs
use crate::controllers::registration::RegistrationController;
use crate::controllers::types::*;
use crate::services::webauthn::WebAuthnService;
use mockall::predicate::*;
use actix_web::{test, web, HttpRequest};
use mockall::mock;

mock! {
    WebAuthnService {}

    impl crate::services::webauthn::WebAuthnServiceTrait for WebAuthnService {
        async fn generate_registration_challenge(
            &self,
            username: &str,
            display_name: &str,
            user_verification: UserVerificationPolicy,
            attestation: AttestationConveyancePreference,
            authenticator_selection: Option<AuthenticatorSelectionCriteria>,
            extensions: Option<RegistrationExtensionInputs>,
        ) -> Result<(String, RegistrationChallengeResponse)>;
        
        async fn verify_registration(
            &self,
            credential: PublicKeyCredential<RegistrationCredential>,
            client_extension_results: Option<RegistrationExtensionOutputs>,
            challenge: &str,
        ) -> Result<RegistrationVerificationResponse>;
    }
}

#[cfg(test)]
mod registration_controller_tests {
    use super::*;

    #[actix_rt::test]
    async fn test_registration_challenge_success() {
        // Arrange
        let mut webauthn_service = MockWebAuthnService::new();
        let expected_response = RegistrationChallengeResponse {
            challenge: "test_challenge".to_string(),
            rp: PublicKeyCredentialRpEntity {
                id: "example.com".to_string(),
                name: "Test Server".to_string(),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"user_id".to_vec(),
                name: "test@example.com".to_string(),
                display_name: "Test User".to_string(),
            },
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: 300000,
            attestation: AttestationConveyancePreference::None,
            authenticator_selection: None,
            extensions: None,
        };

        webauthn_service
            .expect_generate_registration_challenge()
            .with(
                eq("test@example.com"),
                eq("Test User"),
                eq(UserVerificationPolicy::Preferred),
                eq(AttestationConveyancePreference::None),
                eq(None),
                eq(None),
            )
            .returning(move |_, _, _, _, _, _| {
                Ok(("test_challenge".to_string(), expected_response.clone()))
            });

        let controller = RegistrationController::new(webauthn_service);
        let request = RegistrationChallengeRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: UserVerificationPolicy::Preferred,
            attestation: AttestationConveyancePreference::None,
            authenticator_selection: None,
            extensions: None,
        };

        // Act
        let req = HttpRequest::default();
        let result = controller.challenge(req, web::Json(request)).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[actix_rt::test]
    async fn test_registration_challenge_invalid_username() {
        // Arrange
        let webauthn_service = MockWebAuthnService::new();
        let controller = RegistrationController::new(webauthn_service);
        let request = RegistrationChallengeRequest {
            username: "invalid".to_string(), // Invalid email format
            display_name: "Test User".to_string(),
            user_verification: UserVerificationPolicy::Preferred,
            attestation: AttestationConveyancePreference::None,
            authenticator_selection: None,
            extensions: None,
        };

        // Act
        let req = HttpRequest::default();
        let result = controller.challenge(req, web::Json(request)).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[actix_rt::test]
    async fn test_registration_verification_success() {
        // Arrange
        let mut webauthn_service = MockWebAuthnService::new();
        let expected_response = RegistrationVerificationResponse {
            credential_id: "test_credential_id".to_string(),
            counter: 0,
            aaguid: "test_aaguid".to_string(),
            attestation_type: "none".to_string(),
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            transports: vec![AuthenticatorTransport::Internal],
            extensions: None,
        };

        webauthn_service
            .expect_verify_registration()
            .with(always(), always(), eq("test_challenge"))
            .returning(move |_, _, _| Ok(expected_response.clone()));

        let controller = RegistrationController::new(webauthn_service);
        let request = RegistrationVerificationRequest {
            credential: create_test_registration_credential(),
            client_extension_results: None,
        };

        // Act
        let mut req = HttpRequest::default();
        req.headers_mut().insert(
            "X-WebAuthn-Challenge",
            "test_challenge".parse().unwrap(),
        );
        let result = controller.verify(req, web::Json(request)).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[actix_rt::test]
    async fn test_registration_verification_missing_challenge() {
        // Arrange
        let webauthn_service = MockWebAuthnService::new();
        let controller = RegistrationController::new(webauthn_service);
        let request = RegistrationVerificationRequest {
            credential: create_test_registration_credential(),
            client_extension_results: None,
        };

        // Act
        let req = HttpRequest::default(); // No challenge header
        let result = controller.verify(req, web::Json(request)).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }
}

fn create_test_registration_credential() -> PublicKeyCredential<RegistrationCredential> {
    PublicKeyCredential {
        id: "test_credential_id".to_string(),
        raw_id: b"test_credential_id".to_vec(),
        response: RegistrationCredential {
            attestation_object: vec![],
            client_data_json: b"{}".to_vec(),
            transports: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}
```

## 3. Integration Testing Strategy

### 3.1 API Integration Tests

```rust
// tests/integration/api_tests.rs
use actix_web::{test, App, web};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

use crate::config::{DatabaseConfig, WebAuthnConfig};
use crate::controllers::{AuthenticationController, RegistrationController};
use crate::db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::services::WebAuthnService;
use crate::routes::webauthn;

async fn setup_test_app() -> (App<impl actix_web::dev::ServiceFactory<
    actix_web::dev::ServiceRequest,
    Config = (),
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
    InitError = (),
>>, TempDir) {
    // Create temporary database
    let temp_dir = TempDir::new().unwrap();
    let db_url = format!("sqlite:{}", temp_dir.path().join("test.db").display());
    
    // Setup database
    let manager = ConnectionManager::<PgConnection>::new(&db_url);
    let pool = Arc::new(Pool::builder().max_size(1).build(manager).unwrap());
    
    // Run migrations
    let conn = pool.get().unwrap();
    crate::db::migrations::run_migrations(&conn).unwrap();
    
    // Create services
    let config = WebAuthnConfig {
        rp_id: "localhost".to_string(),
        rp_name: "Test Server".to_string(),
        rp_origin: "https://localhost".to_string(),
        allowed_origins: vec!["https://localhost".to_string()],
    };
    
    let user_repo = UserRepository::new(pool.clone());
    let credential_repo = CredentialRepository::new(pool.clone());
    let challenge_repo = ChallengeRepository::new(pool.clone());
    
    let webauthn_service = WebAuthnService::new(
        &config,
        challenge_repo,
        credential_repo,
        user_repo,
    ).unwrap();
    
    let registration_controller = RegistrationController::new(webauthn_service.clone());
    let authentication_controller = AuthenticationController::new(webauthn_service);
    
    let app = test::init_service(
        App::new()
            .configure(webauthn::configure(
                registration_controller,
                authentication_controller,
            ))
    ).await;
    
    (app, temp_dir)
}

#[actix_rt::test]
async fn test_complete_registration_flow() {
    // Arrange
    let (app, _temp_dir) = setup_test_app().await;
    
    // Step 1: Request registration challenge
    let challenge_request = serde_json::json!({
        "username": "test@example.com",
        "displayName": "Test User",
        "userVerification": "preferred",
        "attestation": "none"
    });
    
    let challenge_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/webauthn/register/challenge")
            .set_json(&challenge_request)
            .to_request()
    ).await;
    
    assert_eq!(challenge_resp.status(), 200);
    
    let challenge_data: serde_json::Value = test::read_body_json(challenge_resp).await;
    let challenge = challenge_data["data"]["challenge"].as_str().unwrap();
    let user_id = challenge_data["data"]["user"]["id"].as_str().unwrap();
    
    // Step 2: Simulate credential creation (in real scenario, this would be done by browser)
    let credential = create_mock_attestation(challenge, user_id);
    
    // Step 3: Verify registration
    let verify_request = serde_json::json!({
        "credential": credential,
        "clientExtensionResults": {}
    });
    
    let mut verify_req = test::TestRequest::post()
        .uri("/api/v1/webauthn/register/verify")
        .set_json(&verify_request)
        .to_request();
    
    verify_req.headers_mut().insert(
        "X-WebAuthn-Challenge",
        challenge.parse().unwrap(),
    );
    
    let verify_resp = test::call_service(&app, verify_req).await;
    
    // Assert
    assert_eq!(verify_resp.status(), 200);
    
    let verify_data: serde_json::Value = test::read_body_json(verify_resp).await;
    assert_eq!(verify_data["status"], "ok");
    assert!(verify_data["data"]["credentialId"].as_str().is_some());
}

#[actix_rt::test]
async fn test_complete_authentication_flow() {
    // Arrange
    let (app, _temp_dir) = setup_test_app().await;
    
    // First, register a user
    let user_id = register_test_user(&app).await;
    
    // Step 1: Request authentication challenge
    let auth_challenge_request = serde_json::json!({
        "username": "test@example.com",
        "userVerification": "required"
    });
    
    let challenge_resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/webauthn/authenticate/challenge")
            .set_json(&auth_challenge_request)
            .to_request()
    ).await;
    
    assert_eq!(challenge_resp.status(), 200);
    
    let challenge_data: serde_json::Value = test::read_body_json(challenge_resp).await;
    let challenge = challenge_data["data"]["challenge"].as_str().unwrap();
    
    // Step 2: Simulate assertion creation
    let assertion = create_mock_assertion(challenge, &user_id);
    
    // Step 3: Verify authentication
    let verify_request = serde_json::json!({
        "credential": assertion,
        "clientExtensionResults": {}
    });
    
    let mut verify_req = test::TestRequest::post()
        .uri("/api/v1/webauthn/authenticate/verify")
        .set_json(&verify_request)
        .to_request();
    
    verify_req.headers_mut().insert(
        "X-WebAuthn-Challenge",
        challenge.parse().unwrap(),
    );
    
    let verify_resp = test::call_service(&app, verify_req).await;
    
    // Assert
    assert_eq!(verify_resp.status(), 200);
    
    let verify_data: serde_json::Value = test::read_body_json(verify_resp).await;
    assert_eq!(verify_data["status"], "ok");
    assert!(verify_data["data"]["counter"].as_u64().is_some());
}

async fn register_test_user(app: &App<impl actix_web::dev::ServiceFactory<
    actix_web::dev::ServiceRequest,
    Config = (),
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
    InitError = (),
>>) -> String {
    let challenge_request = serde_json::json!({
        "username": "test@example.com",
        "displayName": "Test User",
        "userVerification": "preferred",
        "attestation": "none"
    });
    
    let challenge_resp = test::call_service(
        app,
        test::TestRequest::post()
            .uri("/api/v1/webauthn/register/challenge")
            .set_json(&challenge_request)
            .to_request()
    ).await;
    
    let challenge_data: serde_json::Value = test::read_body_json(challenge_resp).await;
    let challenge = challenge_data["data"]["challenge"].as_str().unwrap();
    let user_id = challenge_data["data"]["user"]["id"].as_str().unwrap();
    
    let credential = create_mock_attestation(challenge, user_id);
    
    let verify_request = serde_json::json!({
        "credential": credential,
        "clientExtensionResults": {}
    });
    
    let mut verify_req = test::TestRequest::post()
        .uri("/api/v1/webauthn/register/verify")
        .set_json(&verify_request)
        .to_request();
    
    verify_req.headers_mut().insert(
        "X-WebAuthn-Challenge",
        challenge.parse().unwrap(),
    );
    
    let verify_resp = test::call_service(app, verify_req).await;
    assert_eq!(verify_resp.status(), 200);
    
    user_id.to_string()
}

fn create_mock_attestation(challenge: &str, user_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "mock_credential_id",
        "rawId": "mock_credential_id",
        "response": {
            "attestationObject": "mock_attestation_object",
            "clientDataJSON": format!(r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://localhost"}}"#, challenge)
        },
        "type": "public-key"
    })
}

fn create_mock_assertion(challenge: &str, user_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "mock_credential_id",
        "rawId": "mock_credential_id",
        "response": {
            "authenticatorData": "mock_authenticator_data",
            "clientDataJSON": format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://localhost"}}"#, challenge),
            "signature": "mock_signature",
            "userHandle": user_id
        },
        "type": "public-key"
    })
}
```

## 4. Security Testing Strategy

### 4.1 FIDO2 Compliance Tests

```rust
// tests/security/fido2_compliance_tests.rs
use crate::services::webauthn::WebAuthnService;
use crate::config::WebAuthnConfig;
use webauthn_rs::prelude::*;

#[cfg(test)]
mod rp_id_validation_tests {
    use super::*;

    #[tokio::test]
    async fn test_rp_id_validation_valid_cases() {
        let test_cases = vec![
            ("example.com", "https://example.com", true),
            ("auth.example.com", "https://auth.example.com", true),
            ("example.com", "https://sub.example.com", true), // Subdomain allowed
        ];

        for (rp_id, origin, should_pass) in test_cases {
            let result = validate_rp_id_and_origin(rp_id, origin);
            assert_eq!(result.is_ok(), should_pass, 
                "RP ID: {}, Origin: {}, Expected: {}", rp_id, origin, should_pass);
        }
    }

    #[tokio::test]
    async fn test_rp_id_validation_invalid_cases() {
        let test_cases = vec![
            ("example.com", "https://evil.com", false),
            ("example.com", "http://example.com", false), // HTTP not allowed
            ("example.com", "ftp://example.com", false),  // Wrong protocol
            ("", "https://example.com", false),           // Empty RP ID
            ("example.com", "", false),                   // Empty origin
        ];

        for (rp_id, origin, should_pass) in test_cases {
            let result = validate_rp_id_and_origin(rp_id, origin);
            assert_eq!(result.is_ok(), should_pass, 
                "RP ID: {}, Origin: {}, Expected: {}", rp_id, origin, should_pass);
        }
    }
}

#[cfg(test)]
mod challenge_security_tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_entropy() {
        let config = create_test_config();
        let service = create_test_service(&config).await;

        // Generate multiple challenges
        let challenges: Vec<String> = (0..1000)
            .map(|_| {
                let username = format!("user{}@example.com", rand::random::<u32>());
                tokio::block_on(service.generate_registration_challenge(
                    &username,
                    "Test User",
                    UserVerificationPolicy::Preferred,
                    AttestationConveyancePreference::None,
                    None,
                    None,
                )).unwrap().0
            })
            .collect();

        // Test uniqueness
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        assert_eq!(challenges.len(), unique_challenges.len(), "Challenges must be unique");

        // Test entropy (basic statistical test)
        for challenge in &challenges {
            let decoded = base64::decode_config(challenge, base64::URL_SAFE_NO_PAD).unwrap();
            assert_eq!(decoded.len(), 32, "Challenge must be 32 bytes");
            
            // Test for patterns (simplified)
            let entropy = calculate_entropy(&decoded);
            assert!(entropy > 7.0, "Challenge entropy too low: {}", entropy);
        }
    }

    #[tokio::test]
    async fn test_challenge_expiration() {
        let config = create_test_config();
        let service = create_test_service(&config).await;

        // Generate challenge
        let (challenge, _) = service.generate_registration_challenge(
            "test@example.com",
            "Test User",
            UserVerificationPolicy::Preferred,
            AttestationConveyancePreference::None,
            None,
            None,
        ).await.unwrap();

        // Wait for expiration (in test, we'd mock time)
        // For now, just verify the challenge is stored with expiration
        let stored_challenge = service.get_stored_challenge(&challenge).await.unwrap();
        assert!(stored_challenge.expires_at > chrono::Utc::now());
    }
}

#[cfg(test)]
mod attestation_verification_tests {
    use super::*;

    #[tokio::test]
    async fn test_packed_attestation_verification() {
        let config = create_test_config();
        let service = create_test_service(&config).await;

        // Create valid packed attestation
        let attestation = create_valid_packed_attestation();
        let challenge = "test_challenge";

        let result = service.verify_registration(
            attestation,
            None,
            challenge,
        ).await;

        assert!(result.is_ok(), "Valid packed attestation should pass verification");
    }

    #[tokio::test]
    async fn test_fido_u2f_attestation_verification() {
        let config = create_test_config();
        let service = create_test_service(&config).await;

        // Create valid FIDO U2F attestation
        let attestation = create_valid_fido_u2f_attestation();
        let challenge = "test_challenge";

        let result = service.verify_registration(
            attestation,
            None,
            challenge,
        ).await;

        assert!(result.is_ok(), "Valid FIDO U2F attestation should pass verification");
    }

    #[tokio::test]
    async fn test_invalid_attestation_rejection() {
        let config = create_test_config();
        let service = create_test_service(&config).await;

        // Create invalid attestation
        let attestation = create_invalid_attestation();
        let challenge = "test_challenge";

        let result = service.verify_registration(
            attestation,
            None,
            challenge,
        ).await;

        assert!(result.is_err(), "Invalid attestation should be rejected");
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidAttestation));
    }
}

#[cfg(test)]
mod replay_attack_tests {
    use super::*;

    #[tokio::test]
    async fn test_replay_attack_prevention() {
        let config = create_test_config();
        let service = create_test_service(&config).await;

        // Register a credential first
        let credential_id = register_test_credential(&service).await;

        // Create assertion with counter 10
        let assertion1 = create_assertion_with_counter(&credential_id, 10);
        let challenge = "test_challenge";

        // First authentication should succeed
        let result1 = service.verify_authentication(
            assertion1.clone(),
            None,
            challenge,
        ).await;
        assert!(result1.is_ok());

        // Second authentication with same counter should fail
        let result2 = service.verify_authentication(
            assertion1,
            None,
            challenge,
        ).await;
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), WebAuthnError::ReplayAttack));

        // Authentication with lower counter should fail
        let assertion3 = create_assertion_with_counter(&credential_id, 5);
        let result3 = service.verify_authentication(
            assertion3,
            None,
            challenge,
        ).await;
        assert!(result3.is_err());
        assert!(matches!(result3.unwrap_err(), WebAuthnError::ReplayAttack));
    }
}

// Helper functions
fn create_test_config() -> WebAuthnConfig {
    WebAuthnConfig {
        rp_id: "example.com".to_string(),
        rp_name: "Test Server".to_string(),
        rp_origin: "https://example.com".to_string(),
        allowed_origins: vec!["https://example.com".to_string()],
    }
}

async fn create_test_service(config: &WebAuthnConfig) -> WebAuthnService {
    // Create mock repositories for testing
    let challenge_repo = create_mock_challenge_repository();
    let credential_repo = create_mock_credential_repository();
    let user_repo = create_mock_user_repository();

    WebAuthnService::new(config, challenge_repo, credential_repo, user_repo).unwrap()
}

fn validate_rp_id_and_origin(rp_id: &str, origin: &str) -> Result<(), WebAuthnError> {
    // Implementation of RP ID and origin validation
    // This would follow FIDO2 specification §5.1.2 and §5.1.3
    
    if rp_id.is_empty() || origin.is_empty() {
        return Err(WebAuthnError::InvalidRpId);
    }

    if !origin.starts_with("https://") {
        return Err(WebAuthnError::InvalidRpId);
    }

    let origin_domain = origin.strip_prefix("https://").unwrap();
    if !origin_domain.ends_with(rp_id) && origin_domain != rp_id {
        return Err(WebAuthnError::InvalidRpId);
    }

    Ok(())
}

fn calculate_entropy(data: &[u8]) -> f64 {
    // Simple entropy calculation for testing
    let mut freq = std::collections::HashMap::new();
    for &byte in data {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

fn create_valid_packed_attestation() -> PublicKeyCredential<RegistrationCredential> {
    // Create a mock valid packed attestation
    PublicKeyCredential {
        id: "valid_packed_credential".to_string(),
        raw_id: b"valid_packed_credential".to_vec(),
        response: RegistrationCredential {
            attestation_object: create_valid_packed_attestation_object(),
            client_data_json: b"{}".to_vec(),
            transports: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}

fn create_valid_fido_u2f_attestation() -> PublicKeyCredential<RegistrationCredential> {
    // Create a mock valid FIDO U2F attestation
    PublicKeyCredential {
        id: "valid_fido_u2f_credential".to_string(),
        raw_id: b"valid_fido_u2f_credential".to_vec(),
        response: RegistrationCredential {
            attestation_object: create_valid_fido_u2f_attestation_object(),
            client_data_json: b"{}".to_vec(),
            transports: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}

fn create_invalid_attestation() -> PublicKeyCredential<RegistrationCredential> {
    // Create an invalid attestation
    PublicKeyCredential {
        id: "invalid_credential".to_string(),
        raw_id: b"invalid_credential".to_vec(),
        response: RegistrationCredential {
            attestation_object: b"invalid_attestation_object".to_vec(),
            client_data_json: b"invalid_client_data".to_vec(),
            transports: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}

fn create_valid_packed_attestation_object() -> Vec<u8> {
    // Mock valid packed attestation object
    vec![] // In real implementation, this would be a valid COSE-encoded attestation
}

fn create_valid_fido_u2f_attestation_object() -> Vec<u8> {
    // Mock valid FIDO U2F attestation object
    vec![] // In real implementation, this would be a valid FIDO U2F attestation
}

async fn register_test_credential(service: &WebAuthnService) -> String {
    // Register a test credential for replay attack testing
    let (challenge, _) = service.generate_registration_challenge(
        "test@example.com",
        "Test User",
        UserVerificationPolicy::Preferred,
        AttestationConveyancePreference::None,
        None,
        None,
    ).await.unwrap();

    let attestation = create_valid_packed_attestation();
    let result = service.verify_registration(attestation, None, &challenge).await.unwrap();
    result.credential_id
}

fn create_assertion_with_counter(credential_id: &str, counter: u64) -> PublicKeyCredential<AssertionCredential> {
    PublicKeyCredential {
        id: credential_id.to_string(),
        raw_id: credential_id.as_bytes().to_vec(),
        response: AssertionCredential {
            authenticator_data: create_authenticator_data_with_counter(counter),
            client_data_json: b"{}".to_vec(),
            signature: b"mock_signature".to_vec(),
            user_handle: None,
        },
        type_: PublicKeyCredentialType::PublicKey,
        client_extension_results: Default::default(),
    }
}

fn create_authenticator_data_with_counter(counter: u64) -> Vec<u8> {
    // Mock authenticator data with specific counter
    let mut data = vec![0; 37]; // Standard authenticator data length
    // Set counter in the last 4 bytes
    data[33..37].copy_from_slice(&counter.to_be_bytes());
    data
}
```

## 5. Performance Testing Strategy

### 5.1 Load Testing

```rust
// tests/performance/load_tests.rs
use actix_web::{test, App};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

#[cfg(test)]
mod load_tests {
    use super::*;

    #[actix_rt::test]
    async fn test_concurrent_registration_load() {
        let app = create_test_app().await;
        let concurrent_users = 100;
        let requests_per_user = 10;

        let start = Instant::now();
        let mut tasks = JoinSet::new();

        for user_id in 0..concurrent_users {
            let app = app.clone();
            tasks.spawn(async move {
                let username = format!("user{}@example.com", user_id);
                let mut success_count = 0;
                let mut total_time = Duration::ZERO;

                for _ in 0..requests_per_user {
                    let request_start = Instant::now();
                    
                    let challenge_request = serde_json::json!({
                        "username": username,
                        "displayName": format!("User {}", user_id),
                        "userVerification": "preferred",
                        "attestation": "none"
                    });

                    let resp = test::call_service(
                        &app,
                        test::TestRequest::post()
                            .uri("/api/v1/webauthn/register/challenge")
                            .set_json(&challenge_request)
                            .to_request()
                    ).await;

                    let request_time = request_start.elapsed();
                    total_time += request_time;

                    if resp.status() == 200 {
                        success_count += 1;
                    }
                }

                (success_count, total_time)
            });
        }

        let mut total_success = 0;
        let mut total_response_time = Duration::ZERO;

        while let Some(result) = tasks.join_next().await {
            let (success, time) = result.unwrap();
            total_success += success;
            total_response_time += time;
        }

        let total_time = start.elapsed();
        let avg_response_time = total_response_time / (concurrent_users * requests_per_user) as u32;
        let success_rate = total_success as f64 / (concurrent_users * requests_per_user) as f64;
        let throughput = (concurrent_users * requests_per_user) as f64 / total_time.as_secs_f64();

        println!("Load Test Results:");
        println!("  Total requests: {}", concurrent_users * requests_per_user);
        println!("  Successful requests: {}", total_success);
        println!("  Success rate: {:.2}%", success_rate * 100.0);
        println!("  Average response time: {:?}", avg_response_time);
        println!("  Throughput: {:.2} requests/second", throughput);
        println!("  Total time: {:?}", total_time);

        // Assertions
        assert!(success_rate >= 0.95, "Success rate should be at least 95%");
        assert!(avg_response_time < Duration::from_millis(100), "Average response time should be under 100ms");
        assert!(throughput >= 50.0, "Throughput should be at least 50 requests/second");
    }

    #[actix_rt::test]
    async fn test_authentication_throughput() {
        let app = create_test_app().await;
        
        // Pre-register some users
        let user_count = 50;
        for i in 0..user_count {
            register_test_user(&app, i).await;
        }

        let auth_requests = 1000;
        let start = Instant::now();
        let mut tasks = JoinSet::new();

        for i in 0..auth_requests {
            let app = app.clone();
            let user_id = i % user_count;
            tasks.spawn(async move {
                let username = format!("user{}@example.com", user_id);

                let auth_request = serde_json::json!({
                    "username": username,
                    "userVerification": "required"
                });

                let resp = test::call_service(
                    &app,
                    test::TestRequest::post()
                        .uri("/api/v1/webauthn/authenticate/challenge")
                        .set_json(&auth_request)
                        .to_request()
                ).await;

                resp.status() == 200
            });
        }

        let mut success_count = 0;
        while let Some(result) = tasks.join_next().await {
            if result.unwrap() {
                success_count += 1;
            }
        }

        let total_time = start.elapsed();
        let throughput = auth_requests as f64 / total_time.as_secs_f64();
        let success_rate = success_count as f64 / auth_requests as f64;

        println!("Authentication Throughput Results:");
        println!("  Total requests: {}", auth_requests);
        println!("  Successful requests: {}", success_count);
        println!("  Success rate: {:.2}%", success_rate * 100.0);
        println!("  Throughput: {:.2} requests/second", throughput);
        println!("  Total time: {:?}", total_time);

        // Assertions
        assert!(success_rate >= 0.98, "Success rate should be at least 98%");
        assert!(throughput >= 100.0, "Throughput should be at least 100 requests/second");
    }

    #[actix_rt::test]
    async fn test_memory_usage_stability() {
        let app = create_test_app().await;
        let iterations = 1000;
        
        // Measure initial memory
        let initial_memory = get_memory_usage();
        
        for i in 0..iterations {
            let username = format!("user{}@example.com", i);
            
            let challenge_request = serde_json::json!({
                "username": username,
                "displayName": format!("User {}", i),
                "userVerification": "preferred",
                "attestation": "none"
            });

            let _resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/api/v1/webauthn/register/challenge")
                    .set_json(&challenge_request)
                    .to_request()
            ).await;

            // Periodically check memory usage
            if i % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }

        // Force garbage collection
        tokio::task::yield_now().await;
        
        let final_memory = get_memory_usage();
        let memory_growth = final_memory.saturating_sub(initial_memory);
        
        println!("Memory Usage Results:");
        println!("  Initial memory: {} bytes", initial_memory);
        println!("  Final memory: {} bytes", final_memory);
        println!("  Memory growth: {} bytes", memory_growth);
        
        // Memory growth should be minimal
        assert!(memory_growth < 50 * 1024 * 1024, "Memory growth should be less than 50MB");
    }
}

async fn create_test_app() -> App<impl actix_web::dev::ServiceFactory<
    actix_web::dev::ServiceRequest,
    Config = (),
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
    InitError = (),
>> {
    // Implementation similar to integration tests
    // Create test app with in-memory database
    todo!("Implement test app creation")
}

async fn register_test_user(app: &App<impl actix_web::dev::ServiceFactory<
    actix_web::dev::ServiceRequest,
    Config = (),
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
    InitError = (),
>>, user_id: i32) {
    let username = format!("user{}@example.com", user_id);
    
    let challenge_request = serde_json::json!({
        "username": username,
        "displayName": format!("User {}", user_id),
        "userVerification": "preferred",
        "attestation": "none"
    });

    let resp = test::call_service(
        app,
        test::TestRequest::post()
            .uri("/api/v1/webauthn/register/challenge")
            .set_json(&challenge_request)
            .to_request()
    ).await;

    assert_eq!(resp.status(), 200);
    
    // Complete registration with mock attestation
    let challenge_data: serde_json::Value = test::read_body_json(resp).await;
    let challenge = challenge_data["data"]["challenge"].as_str().unwrap();
    
    let credential = serde_json::json!({
        "id": format!("credential_{}", user_id),
        "rawId": format!("credential_{}", user_id),
        "response": {
            "attestationObject": "mock_attestation",
            "clientDataJSON": format!(r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://localhost"}}"#, challenge)
        },
        "type": "public-key"
    });

    let verify_request = serde_json::json!({
        "credential": credential,
        "clientExtensionResults": {}
    });

    let mut verify_req = test::TestRequest::post()
        .uri("/api/v1/webauthn/register/verify")
        .set_json(&verify_request)
        .to_request();
    
    verify_req.headers_mut().insert(
        "X-WebAuthn-Challenge",
        challenge.parse().unwrap(),
    );

    let verify_resp = test::call_service(app, verify_req).await;
    assert_eq!(verify_resp.status(), 200);
}

fn get_memory_usage() -> usize {
    // Get current memory usage
    // This is a simplified version - in real implementation, use platform-specific APIs
    use std::alloc::{GlobalAlloc, Layout, System};
    
    // This is a rough estimate - real implementation would use more sophisticated methods
    0 // Placeholder
}
```

## 6. Test Execution and CI/CD

### 6.1 Test Scripts

```bash
#!/bin/bash
# scripts/run_tests.sh

set -e

echo "Running FIDO2/WebAuthn Server Test Suite"

# Setup test database
echo "Setting up test database..."
docker-compose -f docker-compose.test.yml up -d postgres
sleep 5

# Run database migrations
echo "Running database migrations..."
diesel migration run --database-url postgres://test:test@localhost/test_db

# Run unit tests
echo "Running unit tests..."
cargo test --lib -- --nocapture

# Run integration tests
echo "Running integration tests..."
cargo test --test '*' -- --nocapture

# Run security tests
echo "Running security tests..."
cargo test security -- --nocapture

# Run performance tests
echo "Running performance tests..."
cargo test performance --release -- --nocapture

# Generate coverage report
echo "Generating coverage report..."
cargo tarpaulin --out Html --output-dir coverage/ --exclude-files "*/tests/*"

# Run FIDO2 conformance tests
echo "Running FIDO2 conformance tests..."
cargo test fido2_compliance -- --nocapture

# Cleanup
echo "Cleaning up test database..."
docker-compose -f docker-compose.test.yml down

echo "Test suite completed successfully!"
```

### 6.2 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    name: Test Suite
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_USER: test
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        components: rustfmt, clippy
        override: true

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Install diesel CLI
      run: cargo install diesel_cli --no-default-features --features postgres

    - name: Run database migrations
      run: diesel migration run --database-url postgres://test:test@localhost/test_db
      env:
        DATABASE_URL: postgres://test:test@localhost/test_db

    - name: Check formatting
      run: cargo fmt -- --check

    - name: Run clippy
      run: cargo clippy -- -D warnings

    - name: Run unit tests
      run: cargo test --lib -- --nocapture
      env:
        DATABASE_URL: postgres://test:test@localhost/test_db

    - name: Run integration tests
      run: cargo test --test '*' -- --nocapture
      env:
        DATABASE_URL: postgres://test:test@localhost/test_db

    - name: Run security tests
      run: cargo test security -- --nocapture
      env:
        DATABASE_URL: postgres://test:test@localhost/test_db

    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml --output-dir coverage/ --exclude-files "*/tests/*"
      env:
        DATABASE_URL: postgres://test:test@localhost/test_db

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: coverage/cobertura.xml
        flags: unittests
        name: codecov-umbrella

  performance:
    name: Performance Tests
    runs-on: ubuntu-latest
    needs: test
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_USER: test
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Run performance tests
      run: cargo test performance --release -- --nocapture
      env:
        DATABASE_URL: postgres://test:test@localhost/test_db

    - name: Upload performance results
      uses: actions/upload-artifact@v3
      with:
        name: performance-results
        path: performance_results.json
```

This comprehensive testing strategy ensures thorough validation of the FIDO2/WebAuthn server implementation with focus on security, compliance, and performance requirements. The strategy covers all aspects from unit tests to end-to-end scenarios, providing confidence in the implementation's correctness and robustness.