//! Standalone integration test to verify basic functionality

use actix_web::{test, App, http::StatusCode};
use fido2_webauthn_server::{
    routes::api::configure,
    services::{WebAuthnService, UserService},
    schema::ServerPublicKeyCredentialCreationOptionsRequest,
};

#[actix_web::test]
async fn test_attestation_options_basic() {
    // Create services
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service");

    let user_service = UserService::new();

    // Create test app
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service))
            .app_data(actix_web::web::Data::new(user_service))
            .configure(configure)
    ).await;

    // Create request
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
    };

    // Make request
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Check response
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Try to read response body
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    
    // Try to parse as JSON
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["status"], "ok");
    assert!(response_json["challenge"].as_str().is_some());
    assert!(response_json["rp"]["name"].as_str().is_some());
    assert!(response_json["user"]["name"].as_str().is_some());
}

#[actix_web::test]
async fn test_assertion_options_basic() {
    // Create services
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service");

    let user_service = UserService::new();

    // Create test app
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service))
            .app_data(actix_web::web::Data::new(user_service))
            .configure(configure)
    ).await;

    // Create request
    let request = serde_json::json!({
        "username": "test@example.com",
        "userVerification": "preferred"
    });

    // Make request
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Check response
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Try to read response body
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    
    // Try to parse as JSON
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["status"], "ok");
    assert!(response_json["challenge"].as_str().is_some());
    assert_eq!(response_json["rpId"], "localhost");
}