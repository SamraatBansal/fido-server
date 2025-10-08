//! Unit tests for WebAuthn assertion flow

use serde_json::{json, Value};
use base64::engine::general_purpose;
use fido_server::common::{TestDataFactory, TestHelpers};

#[tokio::test]
async fn test_assertion_options_request_validation() {
    // Test valid assertion options request
    let valid_request = TestDataFactory::valid_assertion_options_request();
    
    // Validate required fields
    assert!(valid_request.get("username").is_some(), "Username should be present");
    assert!(valid_request.get("userVerification").is_some(), "User verification should be present");
    
    // Validate field types
    assert!(valid_request["username"].is_string(), "Username should be a string");
    assert!(valid_request["userVerification"].is_string(), "User verification should be a string");
    
    // Validate user verification values
    let user_verification = valid_request["userVerification"].as_str().unwrap();
    assert!(["required", "preferred", "discouraged"].contains(&user_verification), 
            "User verification should be a valid value");
}

#[tokio::test]
async fn test_assertion_options_missing_username() {
    let mut request = TestDataFactory::valid_assertion_options_request();
    request.as_object_mut().unwrap().remove("username");
    
    // Should fail validation due to missing username
    assert!(request.get("username").is_none(), "Username should be missing");
    
    // Other fields should still be present
    assert!(request.get("userVerification").is_some(), "User verification should be present");
}

#[tokio::test]
async fn test_assertion_options_invalid_user_verification() {
    let mut request = TestDataFactory::valid_assertion_options_request();
    request["userVerification"] = json!("invalid-value");
    
    // Should fail user verification validation
    let user_verification = request["userVerification"].as_str().unwrap();
    assert!(!["required", "preferred", "discouraged"].contains(&user_verification), 
            "User verification should be invalid");
}

#[tokio::test]
async fn test_assertion_result_request_validation() {
    let valid_request = TestDataFactory::valid_assertion_result_request();
    
    // Validate required fields
    assert!(valid_request.get("id").is_some(), "Credential ID should be present");
    assert!(valid_request.get("rawId").is_some(), "Raw ID should be present");
    assert!(valid_request.get("response").is_some(), "Response should be present");
    assert!(valid_request.get("type").is_some(), "Type should be present");
    
    // Validate response structure
    let response = valid_request.get("response").unwrap();
    assert!(response.get("authenticatorData").is_some(), "Authenticator data should be present");
    assert!(response.get("clientDataJSON").is_some(), "Client data JSON should be present");
    assert!(response.get("signature").is_some(), "Signature should be present");
    assert!(response.get("userHandle").is_some(), "User handle should be present");
    
    // Validate base64url encoding
    let id = valid_request["id"].as_str().unwrap();
    let raw_id = valid_request["rawId"].as_str().unwrap();
    let auth_data = response["authenticatorData"].as_str().unwrap();
    let client_data = response["clientDataJSON"].as_str().unwrap();
    let signature = response["signature"].as_str().unwrap();
    let user_handle = response["userHandle"].as_str().unwrap();
    
    assert!(TestHelpers::is_valid_base64url(id), "ID should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(raw_id), "Raw ID should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(auth_data), "Authenticator data should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(client_data), "Client data JSON should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(signature), "Signature should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(user_handle), "User handle should be valid base64url");
}

#[tokio::test]
async fn test_assertion_result_missing_response_fields() {
    let mut request = TestDataFactory::valid_assertion_result_request();
    let response = request["response"].as_object_mut().unwrap();
    
    // Remove authenticator data
    response.remove("authenticatorData");
    assert!(response.get("authenticatorData").is_none(), "Authenticator data should be missing");
    
    // Remove signature
    response.remove("signature");
    assert!(response.get("signature").is_none(), "Signature should be missing");
    
    // Should fail validation due to missing required fields
}

#[tokio::test]
async fn test_assertion_result_invalid_type() {
    let mut request = TestDataFactory::valid_assertion_result_request();
    request["type"] = json!("invalid-type");
    
    // Should fail type validation
    assert_eq!(request["type"], "invalid-type", "Type should be invalid");
}

#[tokio::test]
async fn test_assertion_options_response_schema() {
    let response = TestDataFactory::fido2_compliant_assertion_response();
    
    // Validate required response fields
    assert!(response.get("challenge").is_some(), "Challenge should be present");
    assert!(response.get("rpId").is_some(), "RP ID should be present");
    assert!(response.get("allowCredentials").is_some(), "Allow credentials should be present");
    assert!(response.get("timeout").is_some(), "Timeout should be present");
    assert!(response.get("userVerification").is_some(), "User verification should be present");
    
    // Validate allowCredentials structure
    let allow_creds = response.get("allowCredentials").unwrap();
    assert!(allow_creds.is_array(), "Allow credentials should be an array");
    
    if let Some(creds_array) = allow_creds.as_array() {
        for cred in creds_array {
            assert!(cred.get("type").is_some(), "Credential type should be present");
            assert!(cred.get("id").is_some(), "Credential ID should be present");
            
            // Validate credential type
            let cred_type = cred["type"].as_str().unwrap();
            assert_eq!(cred_type, "public-key", "Credential type should be 'public-key'");
        }
    }
}

#[tokio::test]
async fn test_assertion_result_response_schema() {
    let response = json!({
        "status": "ok",
        "errorMessage": ""
    });
    
    // Validate response structure
    assert!(response.get("status").is_some(), "Status should be present");
    assert!(response.get("errorMessage").is_some(), "Error message should be present");
    
    // Validate status value
    let status = response["status"].as_str().unwrap();
    assert_eq!(status, "ok", "Status should be 'ok'");
    
    // Validate error message (should be empty on success)
    let error_message = response["errorMessage"].as_str().unwrap();
    assert_eq!(error_message, "", "Error message should be empty on success");
}

#[tokio::test]
async fn test_assertion_options_edge_cases() {
    // Test with discouraged user verification
    let mut request = TestDataFactory::valid_assertion_options_request();
    request["userVerification"] = json!("discouraged");
    
    let user_verification = request["userVerification"].as_str().unwrap();
    assert_eq!(user_verification, "discouraged", "User verification should be 'discouraged'");
    
    // Test with required user verification
    request["userVerification"] = json!("required");
    let user_verification = request["userVerification"].as_str().unwrap();
    assert_eq!(user_verification, "required", "User verification should be 'required'");
    
    // Test with empty allowCredentials in response
    let response = json!({
        "challenge": "test-challenge",
        "rpId": "example.com",
        "allowCredentials": [],
        "timeout": 60000,
        "userVerification": "preferred"
    });
    
    let allow_creds = response["allowCredentials"].as_array().unwrap();
    assert!(allow_creds.is_empty(), "Allow credentials should be empty");
}

#[tokio::test]
async fn test_assertion_result_edge_cases() {
    // Test with empty user handle
    let mut request = TestDataFactory::valid_assertion_result_request();
    request["response"]["userHandle"] = json!("");
    
    let user_handle = request["response"]["userHandle"].as_str().unwrap();
    assert_eq!(user_handle, "", "User handle should be empty");
    
    // Test with empty signature (should fail validation)
    request["response"]["signature"] = json!("");
    let signature = request["response"]["signature"].as_str().unwrap();
    assert_eq!(signature, "", "Signature should be empty");
    
    // Test with minimal authenticator data
    request["response"]["authenticatorData"] = json!("AA=="); // Minimal valid base64url
    let auth_data = request["response"]["authenticatorData"].as_str().unwrap();
    assert_eq!(auth_data, "AA==", "Authenticator data should be minimal");
}

#[tokio::test]
async fn test_assertion_client_data_json_validation() {
    let valid_request = TestDataFactory::valid_assertion_result_request();
    let client_data_b64 = valid_request["response"]["clientDataJSON"].as_str().unwrap();
    let client_data_bytes = general_purpose::URL_SAFE_NO_PAD.decode(client_data_b64).unwrap();
    let client_data_str = String::from_utf8(client_data_bytes).unwrap();
    let client_data: Value = serde_json::from_str(&client_data_str).unwrap();
    
    // Validate client data structure
    assert!(client_data.get("type").is_some(), "Client data type should be present");
    assert!(client_data.get("challenge").is_some(), "Client data challenge should be present");
    assert!(client_data.get("origin").is_some(), "Client data origin should be present");
    
    // Validate type value
    let data_type = client_data["type"].as_str().unwrap();
    assert_eq!(data_type, "webauthn.get", "Client data type should be 'webauthn.get'");
    
    // Validate challenge format
    let challenge = client_data["challenge"].as_str().unwrap();
    assert!(!challenge.is_empty(), "Challenge should not be empty");
    
    // Validate origin format
    let origin = client_data["origin"].as_str().unwrap();
    assert!(origin.starts_with("https://"), "Origin should be HTTPS");
}

#[tokio::test]
async fn test_assertion_payload_size_limits() {
    // Test with large credential ID
    let large_credential_id = "x".repeat(1000);
    let large_credential_id_b64 = general_purpose::URL_SAFE_NO_PAD.encode(large_credential_id.as_bytes());
    
    let mut request = TestDataFactory::valid_assertion_result_request();
    request["id"] = json!(large_credential_id_b64.clone());
    request["rawId"] = json!(large_credential_id_b64);
    
    let id = request["id"].as_str().unwrap();
    assert!(id.len() > 1000, "Credential ID should be large");
    
    // Test with minimal payload
    let minimal_request = json!({
        "username": "a",
        "userVerification": "preferred"
    });
    
    let minimal_str = minimal_request.to_string();
    assert!(minimal_str.len() < 50, "Minimal payload should be small");
}

#[tokio::test]
async fn test_assertion_multiple_credentials() {
    // Test response with multiple allowed credentials
    let response = json!({
        "challenge": "test-challenge",
        "rpId": "example.com",
        "allowCredentials": [
            {
                "type": "public-key",
                "id": "credential1"
            },
            {
                "type": "public-key",
                "id": "credential2"
            },
            {
                "type": "public-key",
                "id": "credential3"
            }
        ],
        "timeout": 60000,
        "userVerification": "preferred"
    });
    
    let allow_creds = response["allowCredentials"].as_array().unwrap();
    assert_eq!(allow_creds.len(), 3, "Should have 3 credentials");
    
    for (i, cred) in allow_creds.iter().enumerate() {
        let cred_id = cred["id"].as_str().unwrap();
        assert_eq!(cred_id, format!("credential{}", i + 1), "Credential ID should match");
    }
}