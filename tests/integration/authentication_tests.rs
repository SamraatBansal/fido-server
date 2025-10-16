//! Authentication integration tests for FIDO2/WebAuthn conformance

use actix_test::{self, TestServer};
use actix_web::{App, http};
use serde_json::json;
use fido_server::{routes::api, services::WebAuthnService};

#[actix_web::test]
async fn test_assertion_options_success() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    // First, register a user to have credentials
    let registration_request = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe"
    });

    let _reg_response = app
        .post("/api/attestation/options")
        .send_json(&registration_request)
        .await;

    // Now test assertion options
    let request_body = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let response = app
        .post("/api/assertion/options")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), http::StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    assert_eq!(result["status"], "ok");
    assert!(result["challenge"].as_str().is_some());
    assert_eq!(result["rpId"], "localhost");
    assert_eq!(result["timeout"], 60000);
    assert_eq!(result["userVerification"], "required");
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    let request_body = json!({
        "username": "nonexistent@example.com",
        "userVerification": "preferred"
    });

    let response = app
        .post("/api/assertion/options")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);

    let result: serde_json::Value = response.json().await;
    assert_eq!(result["status"], "failed");
    assert_eq!(result["errorMessage"], "User does not exists!");
}

#[actix_web::test]
async fn test_assertion_options_default_user_verification() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    // First register a user
    let registration_request = json!({
        "username": "test@example.com",
        "displayName": "Test User"
    });

    let _reg_response = app
        .post("/api/attestation/options")
        .send_json(&registration_request)
        .await;

    // Test assertion options without userVerification
    let request_body = json!({
        "username": "test@example.com"
    });

    let response = app
        .post("/api/assertion/options")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), http::StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    assert_eq!(result["status"], "ok");
    assert!(result["challenge"].as_str().is_some());
    // userVerification should not be present in response when not requested
    assert!(result.get("userVerification").is_none());
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    // Mock assertion response (simplified for testing)
    let request_body = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "rawId": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), http::StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_invalid_encoding() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    let request_body = json!({
        "id": "test-id",
        "rawId": "invalid-base64",
        "response": {
            "authenticatorData": "invalid-base64",
            "signature": "invalid-base64",
            "userHandle": "",
            "clientDataJSON": "invalid-base64"
        },
        "type": "public-key"
    });

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);

    let result: serde_json::Value = response.json().await;
    assert_eq!(result["status"], "failed");
    assert!(!result["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_assertion_result_missing_fields() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    let request_body = json!({
        "id": "test-id"
        // Missing required fields
    });

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_health_check() {
    let webauthn_service = WebAuthnService::new().expect("Failed to create WebAuthn service");
    
    let app = TestServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service.clone()))
            .configure(api::configure)
    });

    let response = app.get("/api/health").await;

    assert_eq!(response.status(), http::StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    assert_eq!(result["status"], "healthy");
    assert!(result["timestamp"].as_str().is_some());
}
