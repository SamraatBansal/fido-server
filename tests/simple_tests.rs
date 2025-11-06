use fido2_webauthn_server::*;

#[test]
fn test_server_response_creation() {
    let success = ServerResponse::success();
    assert_eq!(success.status, "ok");
    assert_eq!(success.error_message, "");

    let error = ServerResponse::error("Test error");
    assert_eq!(error.status, "failed");
    assert_eq!(error.error_message, "Test error");
}

#[test]
fn test_api_structs_serialization() {
    let response = ServerPublicKeyCredentialCreationOptionsResponse::new(
        PublicKeyCredentialRpEntity {
            id: Some("example.com".to_string()),
            name: "Example Corp".to_string(),
        },
        ServerPublicKeyCredentialUserEntity {
            id: "dGVzdA".to_string(),
            name: "testuser".to_string(),
            display_name: "Test User".to_string(),
        },
        "Y2hhbGxlbmdl".to_string(),
        vec![PublicKeyCredentialParameters {
            type_: "public-key".to_string(),
            alg: -7,
        }],
        vec![],
        None,
        Some("direct".to_string()),
        Some(60000),
        None,
    );

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("ok"));
    assert!(json.contains("testuser"));
}

#[test]
fn test_validation_functions() {
    use fido2_webauthn_server::error::*;
    
    // Test empty string validation
    assert!(validate_string_not_empty("test", "field").is_ok());
    assert!(validate_string_not_empty("", "field").is_err());
    
    // Test challenge length validation
    let short_challenge = vec![0u8; 10];
    let valid_challenge = vec![0u8; 32];
    let long_challenge = vec![0u8; 100];
    
    assert!(validate_challenge_length(&short_challenge).is_err());
    assert!(validate_challenge_length(&valid_challenge).is_ok());
    assert!(validate_challenge_length(&long_challenge).is_err());
    
    // Test base64url validation
    assert!(validate_base64url("dGVzdA", "field").is_ok());
    assert!(validate_base64url("invalid+/=", "field").is_err());
}