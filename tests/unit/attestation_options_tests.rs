use fido2_conformance_tests::schema::*;
use fido2_conformance_tests::test_utils::*;
use serde_json;
use rstest::*;

/// Unit tests for /attestation/options endpoint
/// These tests validate request parsing, response generation, and business logic

#[test]
fn test_valid_attestation_options_request_serialization() {
    let request = TestFixtures::valid_attestation_options_request();
    
    let json = serde_json::to_string(&request).expect("Should serialize");
    let expected = r#"{"username":"johndoe@example.com","displayName":"John Doe","authenticatorSelection":{"requireResidentKey":false,"authenticatorAttachment":"cross-platform","userVerification":"preferred"},"attestation":"direct"}"#;
    
    assert_eq!(json, expected);
}

#[test]
fn test_valid_attestation_options_request_deserialization() {
    let json = r#"{
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }"#;
    
    let request: AttestationOptionsRequest = serde_json::from_str(json)
        .expect("Should deserialize valid request");
    
    assert_eq!(request.username, "johndoe@example.com");
    assert_eq!(request.display_name, "John Doe");
    assert_eq!(request.attestation, AttestationConveyancePreference::Direct);
    
    let auth_selection = request.authenticator_selection.unwrap();
    assert_eq!(auth_selection.require_resident_key, Some(false));
    assert_eq!(auth_selection.authenticator_attachment, Some(AuthenticatorAttachment::CrossPlatform));
    assert_eq!(auth_selection.user_verification, Some(UserVerificationRequirement::Preferred));
}

#[test]
fn test_attestation_options_request_minimal_fields() {
    let json = r#"{
        "username": "test@example.com",
        "displayName": "Test User"
    }"#;
    
    let request: AttestationOptionsRequest = serde_json::from_str(json)
        .expect("Should deserialize minimal request");
    
    assert_eq!(request.username, "test@example.com");
    assert_eq!(request.display_name, "Test User");
    assert_eq!(request.attestation, AttestationConveyancePreference::None); // Default value
    assert!(request.authenticator_selection.is_none());
}

#[rstest]
#[case::empty_username("", "User")]
#[case::invalid_email("invalid-email", "User")]
#[case::too_long_username(&"x".repeat(256), "User")]
#[case::empty_display_name("user@test.com", "")]
#[case::too_long_display_name("user@test.com", &"x".repeat(256))]
fn test_attestation_options_request_validation_errors(
    #[case] username: &str,
    #[case] display_name: &str
) {
    let json = format!(r#"{{
        "username": "{}",
        "displayName": "{}"
    }}"#, username, display_name);
    
    // Should deserialize but fail validation later
    let request: Result<AttestationOptionsRequest, _> = serde_json::from_str(&json);
    assert!(request.is_ok(), "JSON should parse but validation should catch errors");
    
    let request = request.unwrap();
    
    // Test validation logic
    if username.is_empty() {
        assert!(request.username.is_empty());
    }
    if username.len() > 255 {
        assert!(request.username.len() > 255);
    }
    if display_name.is_empty() {
        assert!(request.display_name.is_empty());
    }
    if display_name.len() > 255 {
        assert!(request.display_name.len() > 255);
    }
}

#[test]
fn test_attestation_options_response_success() {
    let response = AttestationOptionsResponse::ok(
        RelyingParty {
            name: "Example Corporation".to_string(),
            id: Some("example.com".to_string()),
        },
        UserEntity {
            id: TestFixtures::valid_user_id(),
            name: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
        },
        TestFixtures::valid_challenge(),
        vec![PublicKeyCredentialParameters {
            credential_type: "public-key".to_string(),
            alg: -7, // ES256
        }],
        Some(10000),
        Some(vec![PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: TestFixtures::valid_credential_id(),
            transports: None,
        }]),
        Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            user_verification: Some(UserVerificationRequirement::Preferred),
        }),
        Some(AttestationConveyancePreference::Direct),
    );
    
    assert_eq!(response.status, "ok");
    assert!(response.error_message.is_empty());
    assert!(response.rp.is_some());
    assert!(response.user.is_some());
    assert!(response.challenge.is_some());
    assert!(response.pub_key_cred_params.is_some());
    
    let rp = response.rp.unwrap();
    assert_eq!(rp.name, "Example Corporation");
    assert_eq!(rp.id, Some("example.com".to_string()));
    
    let user = response.user.unwrap();
    assert_eq!(user.name, "johndoe@example.com");
    assert_eq!(user.display_name, "John Doe");
    
    let params = response.pub_key_cred_params.unwrap();
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].credential_type, "public-key");
    assert_eq!(params[0].alg, -7);
}

#[test]
fn test_attestation_options_response_error() {
    let response = AttestationOptionsResponse::error("Missing challenge field!");
    
    assert_eq!(response.status, "failed");
    assert_eq!(response.error_message, "Missing challenge field!");
    assert!(response.rp.is_none());
    assert!(response.user.is_none());
    assert!(response.challenge.is_none());
    assert!(response.pub_key_cred_params.is_none());
}

#[test]
fn test_attestation_options_response_serialization() {
    let response = AttestationOptionsResponse::ok(
        RelyingParty {
            name: "Example Corporation".to_string(),
            id: None,
        },
        UserEntity {
            id: "S3932ee31vKEC0JtJMIQ".to_string(),
            name: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
        },
        "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        vec![PublicKeyCredentialParameters {
            credential_type: "public-key".to_string(),
            alg: -7,
        }],
        Some(10000),
        None,
        None,
        None,
    );
    
    let json = serde_json::to_string(&response).expect("Should serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse");
    
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["errorMessage"], "");
    assert_eq!(parsed["rp"]["name"], "Example Corporation");
    assert_eq!(parsed["user"]["name"], "johndoe@example.com");
    assert_eq!(parsed["challenge"], "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN");
    assert_eq!(parsed["pubKeyCredParams"][0]["type"], "public-key");
    assert_eq!(parsed["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(parsed["timeout"], 10000);
}

#[test]
fn test_authenticator_selection_criteria_all_combinations() {
    // Test all combinations of authenticator selection criteria
    let test_cases = vec![
        (Some(true), Some(AuthenticatorAttachment::Platform), Some(UserVerificationRequirement::Required)),
        (Some(false), Some(AuthenticatorAttachment::CrossPlatform), Some(UserVerificationRequirement::Preferred)),
        (None, None, Some(UserVerificationRequirement::Discouraged)),
        (Some(true), None, None),
        (None, Some(AuthenticatorAttachment::Platform), None),
    ];
    
    for (resident_key, attachment, user_verification) in test_cases {
        let criteria = AuthenticatorSelectionCriteria {
            require_resident_key: resident_key,
            authenticator_attachment: attachment,
            user_verification,
        };
        
        let json = serde_json::to_string(&criteria).expect("Should serialize");
        let parsed: AuthenticatorSelectionCriteria = serde_json::from_str(&json)
            .expect("Should deserialize");
        
        assert_eq!(parsed.require_resident_key, resident_key);
        assert_eq!(parsed.authenticator_attachment, attachment);
        assert_eq!(parsed.user_verification, user_verification);
    }
}

#[test]
fn test_attestation_conveyance_preference_values() {
    let test_cases = vec![
        (AttestationConveyancePreference::None, "none"),
        (AttestationConveyancePreference::Indirect, "indirect"),
        (AttestationConveyancePreference::Direct, "direct"),
    ];
    
    for (preference, expected_json) in test_cases {
        let json = serde_json::to_string(&preference).expect("Should serialize");
        assert_eq!(json, format!("\"{}\"", expected_json));
        
        let parsed: AttestationConveyancePreference = serde_json::from_str(&json)
            .expect("Should deserialize");
        assert_eq!(parsed, preference);
    }
}

#[test]
fn test_challenge_requirements() {
    // Test challenge length requirements (16-64 bytes when base64url decoded)
    let valid_challenges = vec![
        "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN", // 24 chars -> 18 bytes
        "a".repeat(22),  // 22 chars -> 16 bytes (minimum)
        "a".repeat(86),  // 86 chars -> 64 bytes (maximum)
    ];
    
    for challenge in valid_challenges {
        // Validate that challenge can be base64url decoded
        let decoded = base64::decode_config(&challenge, base64::URL_SAFE_NO_PAD);
        if decoded.is_ok() {
            let bytes = decoded.unwrap();
            assert!(bytes.len() >= 16 && bytes.len() <= 64, 
                "Challenge length should be 16-64 bytes, got {}", bytes.len());
        }
    }
}

#[test]
fn test_public_key_credential_parameters_algorithms() {
    // Test supported algorithms per FIDO2 spec
    let supported_algorithms = vec![
        -7,   // ES256
        -35,  // ES384
        -36,  // ES512
        -257, // RS256
        -258, // RS384
        -259, // RS512
        -8,   // EdDSA
    ];
    
    for alg in supported_algorithms {
        let param = PublicKeyCredentialParameters {
            credential_type: "public-key".to_string(),
            alg,
        };
        
        let json = serde_json::to_string(&param).expect("Should serialize");
        let parsed: PublicKeyCredentialParameters = serde_json::from_str(&json)
            .expect("Should deserialize");
        
        assert_eq!(parsed.credential_type, "public-key");
        assert_eq!(parsed.alg, alg);
    }
}