//! Integration tests for the FIDO server

use actix_web::{test, App, http};
use fido_server::configure_app;

#[actix_web::test]
async fn test_health_check() {
    let app = test::init_service(
        App::new().configure(configure_app)
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
        App::new().configure(configure_app)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_registration_start() {
    let app = test::init_service(
        App::new().configure(configure_app)
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/register/start")
        .set_json(&serde_json::json!({
            "username": "test@example.com",
            "display_name": "Test User",
            "user_verification": "preferred",
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_authentication_start() {
    let app = test::init_service(
        App::new().configure(configure_app)
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/start")
        .set_json(&serde_json::json!({
            "username": "test@example.com",
            "user_verification": "preferred"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_security_headers() {
    let app = test::init_service(
        App::new().configure(configure_app)
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