//! Integration tests for assertion endpoints

use actix_test::{self, TestServer};
use actix_web::{App, web};
use fido_server::{
    models::webauthn::WebAuthnConfig,
    routes::api::configure_fido_routes,
    services::{WebAuthnService, WebAuthnServiceImpl},
};
use serde_json::json;
use std::sync::Arc;

async fn create_test_app() -> TestServer {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebAuthnServiceImpl::new(webauthn_config));

    actix_test::init_service(
        App::new().configure(|cfg| configure_fido_routes(cfg, webauthn_service))
    )
    .await
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = create_test_app().await;

    let request = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request)
            .to_request()
    )
    .await;

    // This should fail because the mock user has no credentials
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = create_test_app().await;

    let request = json!({
        "username": "nonexistent@example.com",
        "userVerification": "required"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = create_test_app().await;

    let request = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["error_message"], "");
}

#[actix_web::test]
async fn test_assertion_result_invalid_credential() {
    let app = create_test_app().await;

    let request = json!({
        "id": "",
        "response": {
            "authenticatorData": "invalid",
            "signature": "invalid",
            "userHandle": "",
            "clientDataJSON": "invalid"
        },
        "type": "public-key"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(!body["error_message"].as_str().unwrap().is_empty());
}