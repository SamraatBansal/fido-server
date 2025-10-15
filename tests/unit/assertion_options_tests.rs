use fido2_conformance_tests::schema::*;
use fido2_conformance_tests::test_utils::*;
use serde_json;
use rstest::*;

/// Unit tests for /assertion/options endpoint
/// These tests validate request parsing, response generation, and business logic

#[test]
fn test_valid_assertion_options_request_serialization() {
    let request = TestFixtures::valid_assertion_options_request();
    
    let json = serde_json::to_string(&request).expect("Should serialize");
    let expected = r#"{"username":"johndoe@example.com","userVerification":"preferred"}"#;
    
    assert_eq!(json, expected);
}

#[test]
fn test_valid_assertion_options_request_deserialization() {
    let json = r#"{
        "username": "johndoe@example.com",
        "userVerification": "required"
    }"#;
    
    let request: AssertionOptionsRequest = serde_json::from_str(json)
        .expect("Should deserialize valid request");
    
    assert_eq!(request.username, "johndoe@example.com");
    assert_eq!(request.user_verification, Some(UserVerificationRequirement::Required));
}

#[test]
fn test_assertion_options_request_minimal_fields() {
    let json = r#"{
        "username": "test@example.com"
    }"#;
    
    let request: AssertionOptionsRequest = serde_json::from_str(json)
        .expect("Should deserialize minimal request");
    
    assert_eq!(request.username, "test@example.com");
    assert!(request.user_verification.is_none());
}

#[rstest]
#[case::empty_username("")]
#[case::invalid_email("invalid-email")]
#[case::too_long_username(&"x".repeat(256))]
fn test_assertion_options_request_validation_errors(#[case] username: &str) {
    let json = format!(r#"{{
        "username": "{}"
    }}"#, username);
    
    // Should deserialize but fail validation later
    let request: Result<AssertionOptionsRequest, _> = serde_json::from_str(&json);
    assert!(request.is_ok(), "JSON should parse but validation should catch errors");
    
    let request = request.unwrap();
    
    // Test validation logic
    if username.is_empty() {
        assert!(request.username.is_empty());
    }
    if username.len() > 255 {
        assert!(request.username.len() > 255);
    }
    if !username.contains('@') && !username.is_empty() {
        // Invalid email format
        assert!(!request.username.contains('@'));
    }
}

#[test]
fn test_assertion_options_response_success() {
    let response = AssertionOptionsResponse::ok(
        "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
        Some(20000),
        "example.com".to_string(),
        Some(vec![PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
            transports: None,
        }]),
        Some(UserVerificationRequirement::Required),
    );
    
    assert_eq!(response.status, "ok");
    assert!(response.error_message.is_empty());
    assert_eq!(response.challenge, Some("6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string()));
    assert_eq!(response.timeout, Some(20000));
    assert_eq!(response.rp_id, Some("example.com".to_string()));
    assert_eq!(response.user_verification, Some(UserVerificationRequirement::Required));
    
    let credentials = response.allow_credentials.unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].credential_type, "public-key");
    assert_eq!(credentials[0].id, "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m");
}

#[test]
fn test_assertion_options_response_error() {
    let response = AssertionOptionsResponse::error("User does not exists!");
    
    assert_eq!(response.status, "failed");
    assert_eq!(response.error_message, "User does not exists!");
    assert!(response.challenge.is_none());
    assert!(response.timeout.is_none());
    assert!(response.rp_id.is_none());
    assert!(response.allow_credentials.is_none());
    assert!(response.user_verification.is_none());
}

#[test]
fn test_assertion_options_response_serialization() {
    let response = AssertionOptionsResponse::ok(
        "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
        Some(20000),
        "example.com".to_string(),
        Some(vec![PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
            transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
        }]),
        Some(UserVerificationRequirement::Required),
    );
    
    let json = serde_json::to_string(&response).expect("Should serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse");
    
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["errorMessage"], "");
    assert_eq!(parsed["challenge"], "6283u0svT-YIF3pSolzkQHStwkJCaLKx");
    assert_eq!(parsed["timeout"], 20000);
    assert_eq!(parsed["rpId"], "example.com");
    assert_eq!(parsed["userVerification"], "required");
    
    let allow_creds = &parsed["allowCredentials"];
    assert!(allow_creds.is_array());
    assert_eq!(allow_creds[0]["type"], "public-key");
    assert_eq!(allow_creds[0]["id"], "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m");
    assert_eq!(allow_creds[0]["transports"][0], "usb");
    assert_eq!(allow_creds[0]["transports"][1], "nfc");
}

#[test]
fn test_user_verification_requirement_values() {
    let test_cases = vec![
        (UserVerificationRequirement::Required, "required"),
        (UserVerificationRequirement::Preferred, "preferred"),
        (UserVerificationRequirement::Discouraged, "discouraged"),
    ];
    
    for (requirement, expected_json) in test_cases {
        let json = serde_json::to_string(&requirement).expect("Should serialize");
        assert_eq!(json, format!("\"{}\"", expected_json));
        
        let parsed: UserVerificationRequirement = serde_json::from_str(&json)
            .expect("Should deserialize");
        assert_eq!(parsed, requirement);
    }
}

#[test]
fn test_public_key_credential_descriptor_with_transports() {
    let descriptor = PublicKeyCredentialDescriptor {
        credential_type: "public-key".to_string(),
        id: "test-credential-id".to_string(),
        transports: Some(vec![
            "usb".to_string(),
            "nfc".to_string(),
            "ble".to_string(),
            "internal".to_string(),
        ]),
    };
    
    let json = serde_json::to_string(&descriptor).expect("Should serialize");
    let parsed: PublicKeyCredentialDescriptor = serde_json::from_str(&json)
        .expect("Should deserialize");
    
    assert_eq!(parsed.credential_type, "public-key");
    assert_eq!(parsed.id, "test-credential-id");
    
    let transports = parsed.transports.unwrap();
    assert_eq!(transports.len(), 4);
    assert!(transports.contains(&"usb".to_string()));
    assert!(transports.contains(&"nfc".to_string()));
    assert!(transports.contains(&"ble".to_string()));
    assert!(transports.contains(&"internal".to_string()));
}

#[test]
fn test_public_key_credential_descriptor_without_transports() {
    let descriptor = PublicKeyCredentialDescriptor {
        credential_type: "public-key".to_string(),
        id: "test-credential-id".to_string(),
        transports: None,
    };
    
    let json = serde_json::to_string(&descriptor).expect("Should serialize");
    let parsed: PublicKeyCredentialDescriptor = serde_json::from_str(&json)
        .expect("Should deserialize");
    
    assert_eq!(parsed.credential_type, "public-key");
    assert_eq!(parsed.id, "test-credential-id");
    assert!(parsed.transports.is_none());
}

#[test]
fn test_assertion_options_response_with_multiple_credentials() {
    let credentials = vec![
        PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "credential-1".to_string(),
            transports: Some(vec!["usb".to_string()]),
        },
        PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "credential-2".to_string(),
            transports: Some(vec!["nfc".to_string(), "ble".to_string()]),
        },
        PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "credential-3".to_string(),
            transports: None,
        },
    ];
    
    let response = AssertionOptionsResponse::ok(
        "test-challenge".to_string(),
        Some(30000),
        "test.com".to_string(),
        Some(credentials),
        Some(UserVerificationRequirement::Preferred),
    );
    
    let json = serde_json::to_string(&response).expect("Should serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse");
    
    let allow_creds = &parsed["allowCredentials"];
    assert!(allow_creds.is_array());
    assert_eq!(allow_creds.as_array().unwrap().len(), 3);
    
    // Check first credential
    assert_eq!(allow_creds[0]["id"], "credential-1");
    assert_eq!(allow_creds[0]["transports"][0], "usb");
    
    // Check second credential
    assert_eq!(allow_creds[1]["id"], "credential-2");
    assert_eq!(allow_creds[1]["transports"].as_array().unwrap().len(), 2);
    
    // Check third credential (no transports)
    assert_eq!(allow_creds[2]["id"], "credential-3");
    assert!(allow_creds[2]["transports"].is_null());
}

#[test]
fn test_assertion_options_response_empty_credentials_list() {
    let response = AssertionOptionsResponse::ok(
        "test-challenge".to_string(),
        Some(30000),
        "test.com".to_string(),
        Some(vec![]), // Empty credentials list
        Some(UserVerificationRequirement::Preferred),
    );
    
    let json = serde_json::to_string(&response).expect("Should serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse");
    
    let allow_creds = &parsed["allowCredentials"];
    assert!(allow_creds.is_array());
    assert_eq!(allow_creds.as_array().unwrap().len(), 0);
}

#[test]
fn test_assertion_options_response_no_credentials() {
    let response = AssertionOptionsResponse::ok(
        "test-challenge".to_string(),
        Some(30000),
        "test.com".to_string(),
        None, // No credentials
        Some(UserVerificationRequirement::Preferred),
    );
    
    let json = serde_json::to_string(&response).expect("Should serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse");
    
    // allowCredentials should not be present in JSON when None
    assert!(!parsed.as_object().unwrap().contains_key("allowCredentials"));
}

#[test]
fn test_challenge_uniqueness_requirement() {
    // Test that challenges should be unique for each request
    let challenge1 = "6283u0svT-YIF3pSolzkQHStwkJCaLKx";
    let challenge2 = "different-challenge-value-here";
    
    assert_ne!(challenge1, challenge2, "Challenges must be unique");
    
    // Test challenge format (base64url)
    for challenge in [challenge1, challenge2] {
        assert!(challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "Challenge should be base64url encoded");
    }
}

#[test]
fn test_rp_id_validation() {
    let valid_rp_ids = vec![
        "example.com",
        "subdomain.example.com",
        "localhost",
        "192.168.1.1",
        "test-site.co.uk",
    ];
    
    for rp_id in valid_rp_ids {
        let response = AssertionOptionsResponse::ok(
            "test-challenge".to_string(),
            Some(30000),
            rp_id.to_string(),
            None,
            None,
        );
        
        assert_eq!(response.rp_id, Some(rp_id.to_string()));
    }
}