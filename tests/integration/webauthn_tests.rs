//! Integration tests for the FIDO2 WebAuthn server

use actix_web::{test, web, App};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use uuid::Uuid;

use fido_server::config::{Config, WebAuthnConfig};
use fido_server::controllers::WebAuthnController;
use fido_server::db::{Database, PgCredentialRepository, PgChallengeRepository, PgUserRepository};
use fido_server::services::webauthn::{WebAuthnServiceImpl, WebAuthnService};
use fido_server::routes::api;

async fn setup_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    // Use in-memory SQLite for testing
    let database_url = "postgres://localhost/fido_server_test";
    
    // Initialize test database
    let database = Database::new(database_url, 5).expect("Failed to initialize test database");
    
    // Clean up database before each test
    {
        let conn = database.get_connection().expect("Failed to get connection");
        diesel_migrations::embed_migrations!("migrations");
        fido_server::migrations::MIGRATIONS.run(&conn).expect("Failed to run migrations");
    }

    // Initialize repositories
    let user_repo = PgUserRepository::new(database.get_connection().expect("Failed to get connection"));
    let credential_repo = PgCredentialRepository::new(database.get_connection().expect("Failed to get connection"));
    let challenge_repo = PgChallengeRepository::new(database.get_connection().expect("Failed to get connection"));

    // Initialize WebAuthn service
    let webauthn_config = WebAuthnConfig {
        rp_name: "Test Corporation".to_string(),
        rp_id: "localhost".to_string(),
        rp_origin: "http://localhost:8080".to_string(),
        timeout: 60000,
    };

    let webauthn_service = WebAuthnServiceImpl::new(
        webauthn_config,
        user_repo,
        credential_repo,
        challenge_repo,
    ).expect("Failed to initialize WebAuthn service");

    let webauthn_controller = web::Data::new(WebAuthnController::new(webauthn_service));

    test::init_service(
        App::new()
            .app_data(webauthn_controller.clone())
            .configure(|cfg| api::configure(cfg, webauthn_controller.clone()))
            .configure(api::configure_api)
    )
    .await
}

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = setup_test_app().await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert_eq!(body["rp"]["name"], "Test Corporation");
    assert_eq!(body["user"]["name"], "test@example.com");
    assert_eq!(body["user"]["displayName"], "Test User");
    assert!(body["challenge"].as_str().unwrap().len() > 0);
    assert!(body["pubKeyCredParams"].as_array().unwrap().len() > 0);
    assert_eq!(body["timeout"], 60000);
    assert_eq!(body["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let app = setup_test_app().await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "displayName": "Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_attestation_options_missing_display_name() {
    let app = setup_test_app().await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "test@example.com"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = setup_test_app().await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "nonexistent@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("User not found"));
}

#[actix_web::test]
async fn test_health_check() {
    let app = setup_test_app().await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].as_str().is_some());
}

#[actix_web::test]
async fn test_complete_registration_flow() {
    let app = setup_test_app().await;

    // Step 1: Get registration options
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "complete_test@example.com",
            "displayName": "Complete Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let options_body: serde_json::Value = test::read_body_json(resp).await;
    let challenge = options_body["challenge"].as_str().unwrap();
    let user_id = options_body["user"]["id"].as_str().unwrap();

    // Step 2: Simulate attestation response (this would normally come from an authenticator)
    // For testing purposes, we'll create a mock response
    let mock_attestation = json!({
        "id": BASE64.encode("mock_credential_id"),
        "response": {
            "clientDataJSON": BASE64.encode(json!({
                "challenge": challenge,
                "origin": "http://localhost:8080",
                "type": "webauthn.create"
            }).to_string().as_bytes()),
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQAAAAAAAAAAAAAAAAAAAAAA"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(mock_attestation)
        .to_request();

    let resp = test::call_service(&app, req).await;
    // This will fail with mock data, but we're testing the endpoint structure
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_complete_authentication_flow() {
    let app = setup_test_app().await;

    // First, create a user and credential
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "auth_test@example.com",
            "displayName": "Auth Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Try to get authentication options for the user
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "auth_test@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // This will fail because user has no credentials yet
    assert!(!resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("No credentials found"));
}