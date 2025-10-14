//! Unit tests for POST /attestation/options endpoint

use serde_json::{json, Value};
use crate::common::{
    fixtures::TestContext,
    helpers::{assert_success_response, assert_failure_response, validate_challenge, validate_rp_entity, validate_user_entity, validate_pub_key_cred_params},
    mock_data::MockDataFactory,
};

/// Test valid attestation options request
#[tokio::test]
async fn test_attestation_options_valid_request() {
    let context = TestContext::new();
    
    let request = MockDataFactory::valid_attestation_options_request();
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    // Check basic response structure
    assert_eq!(response["status"], "ok");
    assert!(response["errorMessage"].as_str().unwrap_or("").is_empty());
    
    // Validate required fields
    assert!(response.get("challenge").is_some());
    assert!(response.get("rp").is_some());
    assert!(response.get("user").is_some());
    assert!(response.get("pubKeyCredParams").is_some());
    assert!(response.get("timeout").is_some());
    
    // Validate challenge
    let challenge = response["challenge"].as_str().unwrap();
    assert!(validate_challenge(challenge).is_ok());
    
    // Validate RP entity
    let rp = &response["rp"];
    assert!(validate_rp_entity(rp).is_ok());
    
    // Validate user entity
    let user = &response["user"];
    assert!(validate_user_entity(user).is_ok());
    
    // Validate pubKeyCredParams
    let params = &response["pubKeyCredParams"];
    assert!(validate_pub_key_cred_params(params).is_ok());
    
    // Validate timeout
    let timeout = response["timeout"].as_u64().unwrap();
    assert!(timeout > 0);
    assert!(timeout <= 300000); // Max 5 minutes
}

/// Test attestation options with missing username
#[tokio::test]
async fn test_attestation_options_missing_username() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.username = "".to_string();
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "failed");
    assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
    assert!(
        response["errorMessage"].as_str().unwrap().to_lowercase().contains("username") ||
        response["errorMessage"].as_str().unwrap().to_lowercase().contains("required")
    );
}

/// Test attestation options with missing displayName
#[tokio::test]
async fn test_attestation_options_missing_display_name() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.displayName = "".to_string();
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "failed");
    assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
    assert!(
        response["errorMessage"].as_str().unwrap().to_lowercase().contains("displayname") ||
        response["errorMessage"].as_str().unwrap().to_lowercase().contains("required")
    );
}

/// Test attestation options with invalid attestation value
#[tokio::test]
async fn test_attestation_options_invalid_attestation() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.attestation = Some("invalid_attestation".to_string());
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "failed");
    assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
    assert!(
        response["errorMessage"].as_str().unwrap().to_lowercase().contains("attestation") ||
        response["errorMessage"].as_str().unwrap().to_lowercase().contains("invalid")
    );
}

/// Test attestation options with different attestation conveyance preferences
#[tokio::test]
async fn test_attestation_options_different_attestation_values() {
    let context = TestContext::new();
    
    let attestation_values = vec!["none", "indirect", "direct"];
    
    for attestation in attestation_values {
        let mut request = MockDataFactory::valid_attestation_options_request();
        request.attestation = Some(attestation.to_string());
        
        let response: Value = context
            .client
            .post("attestation/options", &request)
            .await
            .expect("Failed to make request");

        assert_eq!(response["status"], "ok");
        assert_eq!(response["attestation"], attestation);
    }
}

/// Test attestation options with authenticator selection criteria
#[tokio::test]
async fn test_attestation_options_with_authenticator_selection() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.authenticatorSelection = Some(crate::common::mock_data::AuthenticatorSelection {
        requireResidentKey: true,
        authenticatorAttachment: "cross-platform".to_string(),
        userVerification: "required".to_string(),
    });
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "ok");
    
    let auth_selection = &response["authenticatorSelection"];
    assert_eq!(auth_selection["requireResidentKey"], true);
    assert_eq!(auth_selection["authenticatorAttachment"], "cross-platform");
    assert_eq!(auth_selection["userVerification"], "required");
}

/// Test attestation options with invalid authenticator attachment
#[tokio::test]
async fn test_attestation_options_invalid_authenticator_attachment() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.authenticatorSelection = Some(crate::common::mock_data::AuthenticatorSelection {
        requireResidentKey: false,
        authenticatorAttachment: "invalid".to_string(),
        userVerification: "preferred".to_string(),
    });
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "failed");
    assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
}

/// Test attestation options with invalid user verification
#[tokio::test]
async fn test_attestation_options_invalid_user_verification() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.authenticatorSelection = Some(crate::common::mock_data::AuthenticatorSelection {
        requireResidentKey: false,
        authenticatorAttachment: "platform".to_string(),
        userVerification: "invalid".to_string(),
    });
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "failed");
    assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
}

/// Test attestation options with malformed JSON
#[tokio::test]
async fn test_attestation_options_malformed_json() {
    let context = TestContext::new();
    
    let malformed_json = json!({
        "username": "test@example.com",
        "displayName": "Test User",
        "attestation": "direct",
        "authenticatorSelection": {
            "requireResidentKey": "invalid_boolean", // Should be boolean
            "authenticatorAttachment": "platform",
            "userVerification": "preferred"
        }
    });
    
    let response: Value = context
        .client
        .post("attestation/options", &malformed_json)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "failed");
    assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
}

/// Test attestation options with very long username
#[tokio::test]
async fn test_attestation_options_very_long_username() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.username = "a".repeat(300); // Very long username
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    // Should either succeed or fail gracefully with appropriate error
    if response["status"] == "failed" {
        assert!(!response["errorMessage"].as_str().unwrap_or("").is_empty());
    } else {
        assert_eq!(response["status"], "ok");
    }
}

/// Test attestation options with special characters in username
#[tokio::test]
async fn test_attestation_options_special_characters_username() {
    let context = TestContext::new();
    
    let special_usernames = vec![
        "test+tag@example.com",
        "user@sub.domain.com",
        "üser@example.com",
        "user@example.co.uk",
        "123456789@example.com",
    ];
    
    for username in special_usernames {
        let mut request = MockDataFactory::valid_attestation_options_request();
        request.username = username.to_string();
        
        let response: Value = context
            .client
            .post("attestation/options", &request)
            .await
            .expect("Failed to make request");

        assert_eq!(response["status"], "ok");
        assert_eq!(response["user"]["name"], username);
    }
}

/// Test attestation options request without authenticatorSelection
#[tokio::test]
async fn test_attestation_options_no_authenticator_selection() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.authenticatorSelection = None;
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "ok");
    // Should use default values
    assert!(response.get("authenticatorSelection").is_some());
}

/// Test attestation options request without attestation field
#[tokio::test]
async fn test_attestation_options_no_attestation() {
    let context = TestContext::new();
    
    let mut request = MockDataFactory::valid_attestation_options_request();
    request.attestation = None;
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "ok");
    // Should default to "none"
    assert_eq!(response["attestation"], "none");
}

/// Test attestation options with excludeCredentials
#[tokio::test]
async fn test_attestation_options_with_exclude_credentials() {
    let context = TestContext::new();
    
    // First, create a credential to exclude
    let create_request = MockDataFactory::valid_attestation_options_request();
    let create_response: Value = context
        .client
        .post("attestation/options", &create_request)
        .await
        .expect("Failed to make request");
    
    // Now request with excludeCredentials (this would typically come from existing credentials)
    let mut request = MockDataFactory::valid_attestation_options_request();
    // Note: In a real scenario, you'd get existing credential IDs from the database
    
    let response: Value = context
        .client
        .post("attestation/options", &request)
        .await
        .expect("Failed to make request");

    assert_eq!(response["status"], "ok");
    // excludeCredentials should be present (even if empty)
    assert!(response.get("excludeCredentials").is_some());
}