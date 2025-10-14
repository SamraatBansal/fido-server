//! Integration tests for FIDO2 server

use actix_web::{test, App};
use fido_server::routes::api;
use serde_json::json;

#[actix_web::test]
async fn test_registration_challenge_success() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
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
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert!(body["challenge"].is_string());
    assert!(body["rp"].is_object());
    assert!(body["user"].is_object());
    assert!(body["pubKeyCredParams"].is_array());
}

#[actix_web::test]
async fn test_registration_challenge_missing_username() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "displayName": "John Doe"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].is_string());
}

#[actix_web::test]
async fn test_registration_challenge_invalid_email() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "username": "invalid-email",
            "displayName": "John Doe"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
}

#[actix_web::test]
async fn test_registration_verify_missing_fields() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "id": "some-id"
            // Missing required fields
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_authentication_challenge_missing_username() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&json!({}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
}

#[actix_web::test]
async fn test_authentication_challenge_user_not_found() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&json!({
            "username": "nonexistent@example.com",
            "userVerification": "preferred"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("not found"));
}

#[actix_web::test]
async fn test_authentication_verify_missing_fields() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&json!({
            "id": "some-id"
            // Missing required fields
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_authentication_verify_credential_not_found() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&json!({
            "id": "nonexistent-credential-id",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    
    // The response should be 404 for credential not found, but currently returns 404
    // Let's verify it's the expected error
    assert_eq!(resp.status(), 404);
    assert!(body["errorMessage"].as_str().unwrap().contains("not found"));
}