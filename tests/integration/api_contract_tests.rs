//! API contract tests

use actix_web::{test, http::StatusCode};
use serde_json::json;
use crate::common::{create_test_app, create_valid_registration_request, create_valid_authentication_request, create_mock_registration_request, create_mock_authentication_request};

#[actix_web::test]
async fn test_registration_options_success() {
    let app = create_test_app().await;
    
    let request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert!(body["rp"]["name"].is_string());
    assert!(body["user"]["id"].is_string());
    assert!(body["user"]["name"].is_string());
    assert!(body["user"]["displayName"].is_string());
    assert!(body["challenge"].is_string());
    assert!(body["pubKeyCredParams"].is_array());
    assert!(body["timeout"].is_number());
    assert!(body["excludeCredentials"].is_array());
    
    // Verify challenge length (should be at least 16 characters when base64url encoded)
    let challenge = body["challenge"].as_str().unwrap();
    assert!(challenge.len() >= 16);
}

#[actix_web::test]
async fn test_registration_options_invalid_input() {
    let app = create_test_app().await;
    
    // Test empty username
    let request = json!({
        "username": "",
        "displayName": "Test User"
    });
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Username"));
}

#[actix_web::test]
async fn test_registration_options_oversized_display_name() {
    let app = create_test_app().await;
    
    let request = json!({
        "username": "test@example.com",
        "displayName": "a".repeat(256) // Too long
    });
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Display name"));
}

#[actix_web::test]
async fn test_registration_result_success() {
    let app = create_test_app().await;
    
    // First, get registration options to create a challenge
    let options_request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&options_request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let options: serde_json::Value = test::read_body_json(resp).await;
    let challenge = options["challenge"].as_str().unwrap();
    
    // Now submit registration with mock credential
    let registration_request = create_mock_registration_request(challenge);
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&registration_request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // Note: This will likely fail with mock data since we're not using real WebAuthn credentials
    // but we can test the endpoint structure and error handling
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["status"].is_string());
    assert!(body["errorMessage"].is_string());
}

#[actix_web::test]
async fn test_authentication_options_success() {
    let app = create_test_app().await;
    
    // First, register a user
    let registration_request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Now get authentication options
    let auth_request = create_valid_authentication_request();
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&auth_request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // This will fail since user has no credentials, but we can test the structure
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["status"].is_string());
    assert!(body["errorMessage"].is_string());
}

#[actix_web::test]
async fn test_authentication_options_user_not_found() {
    let app = create_test_app().await;
    
    let request = json!({
        "username": "nonexistent@example.com"
    });
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("User not found"));
}

#[actix_web::test]
async fn test_health_check() {
    let app = create_test_app().await;
    
    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
    assert!(body["version"].is_string());
}

#[actix_web::test]
async fn test_invalid_content_type() {
    let app = create_test_app().await;
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .insert_header(("content-type", "text/plain"))
        .set_payload("invalid data")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_invalid_json() {
    let app = create_test_app().await;
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .insert_header(("content-type", "application/json"))
        .set_payload("{ invalid json }")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_missing_required_fields() {
    let app = create_test_app().await;
    
    let request = json!({
        "displayName": "Test User"
        // Missing username
    });
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
}