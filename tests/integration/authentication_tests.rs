//! Authentication integration tests

use actix_test::{self, TestServer};
use actix_web::{App, http::StatusCode};
use serde_json::json;
use crate::routes::api::configure;

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let response = app
        .post("/api/assertion/options")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert!(result["challenge"].as_str().unwrap().len() >= 16);
    assert_eq!(result["timeout"], 20000);
    assert_eq!(result["rpId"], "example.com");
    assert_eq!(result["userVerification"], "required");
}

#[actix_web::test]
async fn test_assertion_options_minimal_request() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
        "username": "test@example.com"
    });

    let response = app
        .post("/api/assertion/options")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert!(result["challenge"].as_str().unwrap().len() >= 16);
    assert_eq!(result["timeout"], 20000);
    assert_eq!(result["rpId"], "example.com");
}

#[actix_web::test]
async fn test_assertion_options_missing_username() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
        "userVerification": "required"
    });

    let response = app
        .post("/api/assertion/options")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
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

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_missing_id() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0="
        },
        "type": "public-key"
    });

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_assertion_result_missing_response() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
        "id": "test-id",
        "type": "public-key"
    });

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_assertion_result_missing_authenticator_data() {
    let app = TestServer::new(|| {
        App::new().configure(configure)
    });

    let request_body = json!({
        "id": "test-id",
        "response": {
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0="
        },
        "type": "public-key"
    });

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
