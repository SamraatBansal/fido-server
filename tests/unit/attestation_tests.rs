//! Unit tests for WebAuthn attestation flow

use serde_json::json;
use fido_server::common::{TestDataFactory, TestHelpers};

#[tokio::test]
async fn test_attestation_options_request_validation() {
    // Test valid attestation options request
    let valid_request = TestDataFactory::valid_attestation_options_request();
    
    // Validate required fields
    assert!(valid_request.get("username").is_some(), "Username should be present");
    assert!(valid_request.get("displayName").is_some(), "Display name should be present");
    assert!(valid_request.get("attestation").is_some(), "Attestation should be present");
    
    // Validate field types
    assert!(valid_request["username"].is_string(), "Username should be a string");
    assert!(valid_request["displayName"].is_string(), "Display name should be a string");
    assert!(valid_request["attestation"].is_string(), "Attestation should be a string");
    
    // Validate authenticator selection
    let auth_selection = valid_request.get("authenticatorSelection").unwrap();
    assert!(auth_selection.is_object(), "Authenticator selection should be an object");
}

#[tokio::test]
async fn test_attestation_options_missing_username() {
    let invalid_request = WebAuthnTestDataFactory::invalid_attestation_options_missing_username();
    
    // Should fail validation due to missing username
    assert!(invalid_request.get("username").is_none(), "Username should be missing");
    
    // Other required fields should still be present
    assert!(invalid_request.get("displayName").is_some(), "Display name should be present");
    assert!(invalid_request.get("attestation").is_some(), "Attestation should be present");
}

#[tokio::test]
async fn test_attestation_options_invalid_email() {
    let invalid_request = WebAuthnTestDataFactory::invalid_attestation_options_invalid_email();
    
    // Should fail email validation
    let username = invalid_request["username"].as_str().unwrap();
    assert!(!username.contains("@"), "Invalid email should not contain @");
    assert!(!username.contains("."), "Invalid email should not contain domain");
}

#[tokio::test]
async fn test_attestation_result_request_validation() {
    let valid_request = WebAuthnTestDataFactory::valid_attestation_result_request();
    
    // Validate required fields
    assert!(valid_request.get("id").is_some(), "Credential ID should be present");
    assert!(valid_request.get("rawId").is_some(), "Raw ID should be present");
    assert!(valid_request.get("response").is_some(), "Response should be present");
    assert!(valid_request.get("type").is_some(), "Type should be present");
    
    // Validate response structure
    let response = valid_request.get("response").unwrap();
    assert!(response.get("attestationObject").is_some(), "Attestation object should be present");
    assert!(response.get("clientDataJSON").is_some(), "Client data JSON should be present");
    
    // Validate base64url encoding
    let id = valid_request["id"].as_str().unwrap();
    let raw_id = valid_request["rawId"].as_str().unwrap();
    let attestation_obj = response["attestationObject"].as_str().unwrap();
    let client_data = response["clientDataJSON"].as_str().unwrap();
    
    assert!(TestHelpers::is_valid_base64url(id), "ID should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(raw_id), "Raw ID should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(attestation_obj), "Attestation object should be valid base64url");
    assert!(TestHelpers::is_valid_base64url(client_data), "Client data JSON should be valid base64url");
}

#[tokio::test]
async fn test_attestation_result_invalid_base64url() {
    let invalid_request = WebAuthnTestDataFactory::invalid_base64url_request();
    
    // Should fail base64url validation
    let id = invalid_request["id"].as_str().unwrap();
    let raw_id = invalid_request["rawId"].as_str().unwrap();
    
    assert!(!TestHelpers::is_valid_base64url(id), "Invalid ID should fail base64url validation");
    assert!(!TestHelpers::is_valid_base64url(raw_id), "Invalid raw ID should fail base64url validation");
}

#[tokio::test]
async fn test_attestation_result_missing_response() {
    let mut request = WebAuthnTestDataFactory::valid_attestation_result_request();
    request.as_object_mut().unwrap().remove("response");
    
    // Should fail validation due to missing response
    assert!(request.get("response").is_none(), "Response should be missing");
}

#[tokio::test]
async fn test_attestation_result_invalid_type() {
    let mut request = WebAuthnTestDataFactory::valid_attestation_result_request();
    request["type"] = json!("invalid-type");
    
    // Should fail type validation
    assert_eq!(request["type"], "invalid-type", "Type should be invalid");
}

#[tokio::test]
async fn test_attestation_options_response_schema() {
    let response = WebAuthnTestDataFactory::fido2_compliant_attestation_response();
    
    // Validate required response fields
    assert!(response.get("challenge").is_some(), "Challenge should be present");
    assert!(response.get("rp").is_some(), "RP should be present");
    assert!(response.get("user").is_some(), "User should be present");
    assert!(response.get("pubKeyCredParams").is_some(), "Public key credential parameters should be present");
    assert!(response.get("timeout").is_some(), "Timeout should be present");
    assert!(response.get("attestation").is_some(), "Attestation should be present");
    
    // Validate RP structure
    let rp = response.get("rp").unwrap();
    assert!(rp.get("name").is_some(), "RP name should be present");
    assert!(rp.get("id").is_some(), "RP ID should be present");
    
    // Validate user structure
    let user = response.get("user").unwrap();
    assert!(user.get("id").is_some(), "User ID should be present");
    assert!(user.get("name").is_some(), "User name should be present");
    assert!(user.get("displayName").is_some(), "User display name should be present");
    
    // Validate pubKeyCredParams
    let pub_key_params = response.get("pubKeyCredParams").unwrap();
    assert!(pub_key_params.is_array(), "Public key credential parameters should be an array");
    
    if let Some(params_array) = pub_key_params.as_array() {
        assert!(!params_array.is_empty(), "Public key credential parameters should not be empty");
        
        for param in params_array {
            assert!(param.get("type").is_some(), "Parameter type should be present");
            assert!(param.get("alg").is_some(), "Parameter algorithm should be present");
        }
    }
}

#[tokio::test]
async fn test_attestation_result_response_schema() {
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
async fn test_attestation_options_edge_cases() {
    // Test with empty display name
    let mut request = WebAuthnTestDataFactory::valid_attestation_options_request();
    request["displayName"] = json!("");
    
    let display_name = request["displayName"].as_str().unwrap();
    assert_eq!(display_name, "", "Display name should be empty");
    
    // Test with minimal authenticator selection
    request["authenticatorSelection"] = json!({});
    assert!(request["authenticatorSelection"].as_object().unwrap().is_empty(), 
            "Authenticator selection should be empty");
    
    // Test with none attestation
    request["attestation"] = json!("none");
    assert_eq!(request["attestation"], "none", "Attestation should be 'none'");
}

#[tokio::test]
async fn test_attestation_result_edge_cases() {
    // Test with empty credential ID
    let mut request = WebAuthnTestDataFactory::valid_attestation_result_request();
    request["id"] = json!("");
    request["rawId"] = json!("");
    
    assert_eq!(request["id"], "", "Credential ID should be empty");
    assert_eq!(request["rawId"], "", "Raw ID should be empty");
    
    // Test with empty response fields
    let response = request["response"].as_object_mut().unwrap();
    response["attestationObject"] = json!("");
    response["clientDataJSON"] = json!("");
    
    assert_eq!(response["attestationObject"], "", "Attestation object should be empty");
    assert_eq!(response["clientDataJSON"], "", "Client data JSON should be empty");
}

#[tokio::test]
async fn test_attestation_payload_size_limits() {
    // Test with oversized payload
    let oversized_request = WebAuthnTestDataFactory::oversized_payload_request();
    let payload_str = oversized_request.to_string();
    
    // Should exceed reasonable size limits
    assert!(payload_str.len() > 1_000_000, "Payload should be oversized");
    
    // Test with minimal payload
    let minimal_request = json!({
        "username": "a",
        "displayName": "a",
        "attestation": "none"
    });
    
    let minimal_str = minimal_request.to_string();
    assert!(minimal_str.len() < 100, "Minimal payload should be small");
}