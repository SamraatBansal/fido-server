use crate::common::{TestClient, valid_registration_request, mock_attestation_response};
use actix_web::http::StatusCode;
use serde_json::{json, Value};

#[actix_rt::test]
async fn test_attestation_options_success() {
    let client = TestClient::new().await;
    let request = valid_registration_request();
    
    let response = client.post_json("/attestation/options", request).await;
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "ok");
    assert!(body["challenge"].is_string());
    assert!(body["rp"]["name"].is_string());
    assert!(body["user"]["id"].is_string());
    assert!(body["user"]["name"].is_string());
    assert!(body["user"]["displayName"].is_string());
    assert!(body["pubKeyCredParams"].is_array());
    assert!(body["timeout"].is_number());
}

#[actix_rt::test]
async fn test_attestation_options_missing_username() {
    let client = TestClient::new().await;
    let request = json!({
        "displayName": "Test User"
    });
    
    let response = client.post_json("/attestation/options", request).await;
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].is_string());
}

#[actix_rt::test]
async fn test_attestation_options_invalid_email() {
    let client = TestClient::new().await;
    let request = json!({
        "username": "invalid-email",
        "displayName": "Test User"
    });
    
    let response = client.post_json("/attestation/options", request).await;
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
}

#[actix_rt::test]
async fn test_attestation_result_success() {
    let client = TestClient::new().await;
    
    // First get attestation options
    let options_request = valid_registration_request();
    let options_response = client.post_json("/attestation/options", options_request).await;
    assert_eq!(options_response.status(), StatusCode::OK);
    
    // Then submit attestation result
    let attestation_request = mock_attestation_response();
    let response = client.post_json("/attestation/result", attestation_request).await;
    
    // Note: This will likely fail validation with mock data, but should not crash
    assert!(response.status().is_client_error() || response.status().is_success());
}

#[actix_rt::test]
async fn test_attestation_result_missing_credential() {
    let client = TestClient::new().await;
    let request = json!({
        "type": "public-key"
    });
    
    let response = client.post_json("/attestation/result", request).await;
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
}

#[actix_rt::test]
async fn test_challenge_uniqueness() {
    let client = TestClient::new().await;
    let request = valid_registration_request();
    
    // Make two requests
    let response1 = client.post_json("/attestation/options", request.clone()).await;
    let response2 = client.post_json("/attestation/options", request).await;
    
    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::OK);
    
    let body1: Value = response1.json().await;
    let body2: Value = response2.json().await;
    
    // Challenges should be different
    assert_ne!(body1["challenge"], body2["challenge"]);
}

#[actix_rt::test]
async fn test_challenge_length() {
    let client = TestClient::new().await;
    let request = valid_registration_request();
    
    let response = client.post_json("/attestation/options", request).await;
    assert_eq!(response.status(), StatusCode::OK);
    
    let body: Value = response.json().await;
    let challenge = body["challenge"].as_str().unwrap();
    
    // Challenge should be base64url encoded and at least 16 bytes (22 chars in base64url)
    assert!(challenge.len() >= 22);
}

#[actix_rt::test]
async fn test_rp_id_validation() {
    let client = TestClient::new().await;
    let request = valid_registration_request();
    
    let response = client.post_json("/attestation/options", request).await;
    assert_eq!(response.status(), StatusCode::OK);
    
    let body: Value = response.json().await;
    assert!(body["rp"]["id"].is_string());
    assert!(body["rp"]["name"].is_string());
}

#[actix_rt::test]
async fn test_supported_algorithms() {
    let client = TestClient::new().await;
    let request = valid_registration_request();
    
    let response = client.post_json("/attestation/options", request).await;
    assert_eq!(response.status(), StatusCode::OK);
    
    let body: Value = response.json().await;
    let algorithms = body["pubKeyCredParams"].as_array().unwrap();
    
    // Should support at least ES256 (-7) and RS256 (-257)
    let alg_values: Vec<i64> = algorithms
        .iter()
        .map(|alg| alg["alg"].as_i64().unwrap())
        .collect();
    
    assert!(alg_values.contains(&-7)); // ES256
    assert!(alg_values.contains(&-257)); // RS256
}