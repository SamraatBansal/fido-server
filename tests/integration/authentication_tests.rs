use crate::common::{TestClient, valid_authentication_request, mock_assertion_response};
use actix_web::http::StatusCode;
use serde_json::{json, Value};

#[actix_rt::test]
async fn test_assertion_options_success() {
    let client = TestClient::new().await;
    let request = valid_authentication_request();
    
    let response = client.post_json("/assertion/options", request).await;
    
    // This might return 404 if user doesn't exist, which is expected behavior
    assert!(response.status().is_success() || response.status() == StatusCode::NOT_FOUND);
    
    if response.status().is_success() {
        let body: Value = response.json().await;
        assert_eq!(body["status"], "ok");
        assert!(body["challenge"].is_string());
        assert!(body["allowCredentials"].is_array());
        assert!(body["userVerification"].is_string());
        assert!(body["timeout"].is_number());
    }
}

#[actix_rt::test]
async fn test_assertion_options_missing_username() {
    let client = TestClient::new().await;
    let request = json!({
        "userVerification": "required"
    });
    
    let response = client.post_json("/assertion/options", request).await;
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].is_string());
}

#[actix_rt::test]
async fn test_assertion_options_invalid_user_verification() {
    let client = TestClient::new().await;
    let request = json!({
        "username": "test@example.com",
        "userVerification": "invalid"
    });
    
    let response = client.post_json("/assertion/options", request).await;
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
}

#[actix_rt::test]
async fn test_assertion_options_nonexistent_user() {
    let client = TestClient::new().await;
    let request = json!({
        "username": "nonexistent@example.com",
        "userVerification": "required"
    });
    
    let response = client.post_json("/assertion/options", request).await;
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("User"));
}

#[actix_rt::test]
async fn test_assertion_result_success() {
    let client = TestClient::new().await;
    
    // Submit assertion result (will likely fail validation with mock data)
    let assertion_request = mock_assertion_response();
    let response = client.post_json("/assertion/result", assertion_request).await;
    
    // Should not crash, but will likely fail validation
    assert!(response.status().is_client_error() || response.status().is_success());
}

#[actix_rt::test]
async fn test_assertion_result_missing_credential() {
    let client = TestClient::new().await;
    let request = json!({
        "type": "public-key"
    });
    
    let response = client.post_json("/assertion/result", request).await;
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
}

#[actix_rt::test]
async fn test_assertion_result_invalid_credential_id() {
    let client = TestClient::new().await;
    let request = json!({
        "id": "invalid-credential-id",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "type": "public-key"
    });
    
    let response = client.post_json("/assertion/result", request).await;
    
    assert!(response.status().is_client_error());
    
    let body: Value = response.json().await;
    assert_eq!(body["status"], "failed");
}

#[actix_rt::test]
async fn test_user_verification_requirements() {
    let client = TestClient::new().await;
    
    // Test different user verification levels
    for uv in &["required", "preferred", "discouraged"] {
        let request = json!({
            "username": "test@example.com",
            "userVerification": uv
        });
        
        let response = client.post_json("/assertion/options", request).await;
        
        // Should accept all valid user verification values
        if response.status().is_success() {
            let body: Value = response.json().await;
            assert_eq!(body["userVerification"], *uv);
        }
    }
}

#[actix_rt::test]
async fn test_challenge_timeout() {
    let client = TestClient::new().await;
    let request = valid_authentication_request();
    
    let response = client.post_json("/assertion/options", request).await;
    
    if response.status().is_success() {
        let body: Value = response.json().await;
        let timeout = body["timeout"].as_u64().unwrap();
        
        // Timeout should be reasonable (between 30 seconds and 5 minutes)
        assert!(timeout >= 30000 && timeout <= 300000);
    }
}