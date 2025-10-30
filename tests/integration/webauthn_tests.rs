use actix_web::{test, web, App};
use serde_json::json;
use fido_server::{
    controllers::WebAuthnController,
    services::{WebAuthnService, WebAuthnServiceImpl},
    repositories::{UserRepository, CredentialRepository, ChallengeRepository},
    dtos::*,
    error::Result,
};
use std::sync::Arc;
use uuid::Uuid;
use mockall::mock;
use async_trait::async_trait;

// Mock implementations for testing
mock! {
    UserRepository {}

    #[async_trait]
    impl UserRepository for UserRepository {
        async fn find_by_username(&self, username: &str) -> Result<Option<fido_server::models::User>>;
        async fn create_user(&self, user: &fido_server::models::NewUser) -> Result<fido_server::models::User>;
        async fn find_by_id(&self, id: Uuid) -> Result<Option<fido_server::models::User>>;
    }
}

mock! {
    CredentialRepository {}

    #[async_trait]
    impl CredentialRepository for CredentialRepository {
        async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<fido_server::models::Credential>>;
        async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<fido_server::models::Credential>>;
        async fn create_credential(&self, credential: &fido_server::models::NewCredential) -> Result<fido_server::models::Credential>;
        async fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()>;
    }
}

mock! {
    ChallengeRepository {}

    #[async_trait]
    impl ChallengeRepository for ChallengeRepository {
        async fn create_challenge(&self, challenge: &fido_server::models::NewChallenge) -> Result<fido_server::models::Challenge>;
        async fn find_and_consume_challenge(&self, challenge: &str, challenge_type: &str) -> Result<Option<fido_server::models::Challenge>>;
        async fn cleanup_expired_challenges(&self) -> Result<()>;
    }
}

#[tokio::test]
async fn test_attestation_options_success() {
    // Arrange
    let mut mock_user_repo = MockUserRepository::new();
    let mut mock_credential_repo = MockCredentialRepository::new();
    let mut mock_challenge_repo = MockChallengeRepository::new();

    // Mock user not found (will be created)
    mock_user_repo
        .expect_find_by_username()
        .with(mockall::predicate::eq("johndoe@example.com"))
        .times(1)
        .returning(|_| Ok(None));

    // Mock user creation
    mock_user_repo
        .expect_create_user()
        .times(1)
        .returning(|user| Ok(fido_server::models::User {
            id: user.id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }));

    // Mock no existing credentials
    mock_credential_repo
        .expect_find_by_user_id()
        .times(1)
        .returning(|_| Ok(vec![]));

    // Mock challenge creation
    mock_challenge_repo
        .expect_create_challenge()
        .times(1)
        .returning(|challenge| Ok(fido_server::models::Challenge {
            id: challenge.id,
            user_id: challenge.user_id,
            challenge: challenge.challenge.clone(),
            challenge_type: challenge.challenge_type.clone(),
            expires_at: challenge.expires_at,
            used: false,
            created_at: chrono::Utc::now(),
        }));

    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(
        Arc::new(mock_user_repo),
        Arc::new(mock_credential_repo),
        Arc::new(mock_challenge_repo),
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    ).unwrap());

    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .configure(|cfg| fido_server::controllers::configure_standard_routes(cfg, controller.clone()))
    ).await;

    // Act
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Assert
    assert!(resp.status().is_success());

    let body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
    assert_eq!(body.rp.name, "Example Corporation");
    assert_eq!(body.user.name, "johndoe@example.com");
    assert_eq!(body.user.display_name, "John Doe");
    assert!(!body.challenge.is_empty());
    assert!(!body.pub_key_cred_params.is_empty());
    assert_eq!(body.timeout, Some(60000));
}

#[tokio::test]
async fn test_attestation_options_missing_username() {
    let app = test::init_service(
        App::new()
            .configure(|cfg| fido_server::controllers::configure_standard_routes(cfg, Arc::new(WebAuthnController::new(
                Arc::new(WebAuthnServiceImpl::new(
                    Arc::new(MockUserRepository::new()),
                    Arc::new(MockCredentialRepository::new()),
                    Arc::new(MockChallengeRepository::new()),
                    "Example Corporation".to_string(),
                    "localhost".to_string(),
                    "http://localhost:3000".to_string(),
                ).unwrap())
            ))))
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "displayName": "John Doe"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());
}

#[tokio::test]
async fn test_assertion_options_success() {
    // Arrange
    let mut mock_user_repo = MockUserRepository::new();
    let mut mock_credential_repo = MockCredentialRepository::new();
    let mut mock_challenge_repo = MockChallengeRepository::new();

    let user_id = Uuid::new_v4();
    
    // Mock user found
    mock_user_repo
        .expect_find_by_username()
        .with(mockall::predicate::eq("johndoe@example.com"))
        .times(1)
        .returning(move |_| Ok(Some(fido_server::models::User {
            id: user_id,
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })));

    // Mock existing credentials
    mock_credential_repo
        .expect_find_by_user_id()
        .with(mockall::predicate::eq(user_id))
        .times(1)
        .returning(move |_| Ok(vec![fido_server::models::Credential {
            id: Uuid::new_v4(),
            user_id,
            credential_id: b"test_credential_id".to_vec(),
            public_key: b"test_public_key".to_vec(),
            sign_count: 0,
            attestation_format: "none".to_string(),
            attestation_data: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }]));

    // Mock challenge creation
    mock_challenge_repo
        .expect_create_challenge()
        .times(1)
        .returning(|challenge| Ok(fido_server::models::Challenge {
            id: challenge.id,
            user_id: challenge.user_id,
            challenge: challenge.challenge.clone(),
            challenge_type: challenge.challenge_type.clone(),
            expires_at: challenge.expires_at,
            used: false,
            created_at: chrono::Utc::now(),
        }));

    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(
        Arc::new(mock_user_repo),
        Arc::new(mock_credential_repo),
        Arc::new(mock_challenge_repo),
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    ).unwrap());

    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .configure(|cfg| fido_server::controllers::configure_standard_routes(cfg, controller.clone()))
    ).await;

    // Act
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Assert
    assert!(resp.status().is_success());

    let body: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.rp_id, "localhost");
    assert!(!body.allow_credentials.is_empty());
    assert_eq!(body.user_verification, Some("required".to_string()));
}

#[tokio::test]
async fn test_assertion_options_user_not_found() {
    let mut mock_user_repo = MockUserRepository::new();
    let mock_credential_repo = MockCredentialRepository::new();
    let mock_challenge_repo = MockChallengeRepository::new();

    // Mock user not found
    mock_user_repo
        .expect_find_by_username()
        .with(mockall::predicate::eq("nonexistent@example.com"))
        .times(1)
        .returning(|_| Ok(None));

    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(
        Arc::new(mock_user_repo),
        Arc::new(mock_credential_repo),
        Arc::new(mock_challenge_repo),
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    ).unwrap());

    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .configure(|cfg| fido_server::controllers::configure_standard_routes(cfg, controller.clone()))
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "nonexistent@example.com"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_assertion_result_success() {
    // Arrange
    let mock_user_repo = MockUserRepository::new();
    let mut mock_credential_repo = MockCredentialRepository::new();
    let mut mock_challenge_repo = MockChallengeRepository::new();

    // Mock challenge found and consumed
    mock_challenge_repo
        .expect_find_and_consume_challenge()
        .times(1)
        .returning(|_, _| Ok(Some(fido_server::models::Challenge {
            id: Uuid::new_v4(),
            user_id: None,
            challenge: "dGVzdF9jaGFsbGVuZ2U=".to_string(), // base64 of "test_challenge"
            challenge_type: "authentication".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            used: false,
            created_at: chrono::Utc::now(),
        })));

    // Mock credential found
    mock_credential_repo
        .expect_find_by_credential_id()
        .times(1)
        .returning(|_| Ok(Some(fido_server::models::Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: b"test_credential_id".to_vec(),
            public_key: b"test_public_key".to_vec(),
            sign_count: 0,
            attestation_format: "none".to_string(),
            attestation_data: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })));

    // Mock sign count update
    mock_credential_repo
        .expect_update_sign_count()
        .times(1)
        .returning(|_, _| Ok(()));

    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(
        Arc::new(mock_user_repo),
        Arc::new(mock_credential_repo),
        Arc::new(mock_challenge_repo),
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    ).unwrap());

    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .configure(|cfg| fido_server::controllers::configure_standard_routes(cfg, controller.clone()))
    ).await;

    // Act
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(json!({
            "id": "dGVzdF9jcmVkZW50aWFsX2lk", // base64 of "test_credential_id"
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0X2NoYWxsZW5nZSIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ"
            },
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Debug: print status
    println!("Response status: {}", resp.status());
    
    // Assert
    assert!(resp.status().is_success());

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}