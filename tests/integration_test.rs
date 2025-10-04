//! Integration tests for the FIDO server

use actix_web::{test, App, web};
use fido_server::controllers::health_check;
use fido_server::routes::{configure_api_routes, configure_health_routes};
use fido_server::middleware::{configure_cors, security_headers};
use fido_server::services::{WebAuthnService, ChallengeService, CredentialService, UserService};
use fido_server::config::WebAuthnConfig;
use std::sync::Mutex;

#[actix_web::test]
async fn test_health_check() {
    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .wrap(configure_cors())
            .service(configure_health_routes())
            .route("/health", actix_web::web::get().to(health_check))
    ).await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_api_health_check() {
    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .wrap(configure_cors())
            .service(configure_api_routes())
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_registration_start_with_service() {
    // Initialize services
    let config = WebAuthnConfig::default();
    let challenge_service = ChallengeService::new();
    let credential_service = CredentialService::new();
    let user_service = UserService::new();
    
    let webauthn_service = WebAuthnService::new(
        config,
        challenge_service,
        credential_service,
        user_service,
    ).unwrap();

    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .wrap(configure_cors())
            .app_data(web::Data::new(Mutex::new(webauthn_service)))
            .service(configure_api_routes())
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/register/start")
        .set_json(&serde_json::json!({
            "username": "testuser",
            "display_name": "Test User",
            "user_verification": "preferred",
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let body = test::read_body(resp).await;
    let response_text = String::from_utf8_lossy(&body);
    assert!(response_text.contains("challenge_id"));
    assert!(response_text.contains("publicKey"));
}

#[actix_web::test]
async fn test_authentication_start_with_service() {
    // Initialize services
    let config = WebAuthnConfig::default();
    let challenge_service = ChallengeService::new();
    let credential_service = CredentialService::new();
    let user_service = UserService::new();
    
    let webauthn_service = WebAuthnService::new(
        config,
        challenge_service,
        credential_service,
        user_service,
    ).unwrap();

    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .wrap(configure_cors())
            .app_data(web::Data::new(Mutex::new(webauthn_service)))
            .service(configure_api_routes())
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/start")
        .set_json(&serde_json::json!({
            "username": "testuser",
            "user_verification": "preferred"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let body = test::read_body(resp).await;
    let response_text = String::from_utf8_lossy(&body);
    assert!(response_text.contains("challenge_id"));
    assert!(response_text.contains("publicKey"));
}

#[actix_web::test]
async fn test_security_headers() {
    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .wrap(configure_cors())
            .route("/health", actix_web::web::get().to(health_check))
    ).await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    // Check for security headers
    assert_eq!(
        resp.headers().get("Strict-Transport-Security").unwrap(),
        "max-age=31536000; includeSubDomains; preload"
    );
    assert_eq!(
        resp.headers().get("X-Content-Type-Options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        resp.headers().get("X-Frame-Options").unwrap(),
        "DENY"
    );
}