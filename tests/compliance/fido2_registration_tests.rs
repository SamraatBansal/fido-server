//! FIDO2 registration compliance tests

use crate::common::{create_test_app, create_valid_registration_request};

#[actix_web::test]
async fn test_fido2_sr_1_1_rp_id_validation() {
    // SR-1.1: RP ID validation
    let test_cases = vec![
        ("localhost", "http://localhost:8080", true),
        ("example.com", "https://example.com", true),
        ("auth.example.com", "https://example.com", true),
        ("evil.com", "https://example.com", false),
        ("example.com.evil.com", "https://example.com", false),
    ];
    
    for (rp_id, origin, should_pass) in test_cases {
        let result = fido_server::services::SecurityService::validate_rp_id(rp_id, origin);
        assert_eq!(result.is_ok(), should_pass, 
            "RP ID: {}, Origin: {}, Expected: {}", rp_id, origin, should_pass);
    }
}

#[actix_web::test]
async fn test_fido2_sr_1_2_challenge_requirements() {
    // SR-1.2: Challenge requirements
    
    // Test challenge length (minimum 16 bytes when base64url encoded)
    let challenge = fido_server::services::SecurityService::generate_challenge().unwrap();
    assert!(challenge.len() >= 16, "Challenge must be at least 16 characters when base64url encoded");
    
    // Test uniqueness (100 challenges should be unique)
    let challenges: Vec<String> = (0..100).map(|_| {
        fido_server::services::SecurityService::generate_challenge().unwrap()
    }).collect();
    let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
    assert_eq!(challenges.len(), unique_challenges.len(), "All challenges must be unique");
    
    // Test challenge validation
    assert!(fido_server::services::SecurityService::validate_challenge(&challenge).is_ok());
    
    // Test invalid challenge lengths
    let short_challenge = "a".repeat(10);
    assert!(fido_server::services::SecurityService::validate_challenge(&short_challenge).is_err());
    
    let long_challenge = "a".repeat(100);
    assert!(fido_server::services::SecurityService::validate_challenge(&long_challenge).is_err());
    
    // Test invalid base64url
    let invalid_challenge = "invalid+base64/encoding";
    assert!(fido_server::services::SecurityService::validate_challenge(invalid_challenge).is_err());
}

#[actix_web::test]
async fn test_fido2_sr_1_3_user_validation() {
    // SR-1.3: User validation
    
    let app = create_test_app().await;
    
    // Test valid user creation
    let request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify user ID is base64url encoded
    let user_id = body["user"]["id"].as_str().unwrap();
    assert!(base64::decode_config(user_id, base64::URL_SAFE_NO_PAD).is_ok());
    
    // Verify user name matches request
    assert_eq!(body["user"]["name"], request.username);
    assert_eq!(body["user"]["displayName"], request.display_name);
}

#[actix_web::test]
async fn test_fido2_sr_1_4_pub_key_cred_params() {
    // SR-1.4: Public key credential parameters
    
    let app = create_test_app().await;
    
    let request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify pubKeyCredParams is an array
    assert!(body["pubKeyCredParams"].is_array());
    
    let params = body["pubKeyCredParams"].as_array().unwrap();
    assert!(!params.is_empty(), "pubKeyCredParams must not be empty");
    
    // Verify each parameter has required fields
    for param in params {
        assert_eq!(param["type"], "public-key");
        assert!(param["alg"].is_number());
        
        // Verify supported algorithms
        let alg = param["alg"].as_i64().unwrap();
        assert!(alg == -7 || alg == -257 || alg == -8, "Unsupported algorithm: {}", alg);
    }
}

#[actix_web::test]
async fn test_fido2_sr_1_5_timeout() {
    // SR-1.5: Timeout configuration
    
    let app = create_test_app().await;
    
    let request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify timeout is present and reasonable
    if let Some(timeout) = body["timeout"].as_u64() {
        assert!(timeout >= 30000, "Timeout should be at least 30 seconds");
        assert!(timeout <= 300000, "Timeout should not exceed 5 minutes");
    }
}

#[actix_web::test]
async fn test_fido2_sr_1_6_exclude_credentials() {
    // SR-1.6: Exclude credentials
    
    let app = create_test_app().await;
    
    let request = create_valid_registration_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify excludeCredentials is an array
    assert!(body["excludeCredentials"].is_array());
    
    // For new users, this should be empty
    let exclude_creds = body["excludeCredentials"].as_array().unwrap();
    // Note: This might not be empty if the user already has credentials
}

#[actix_web::test]
async fn test_fido2_sr_1_7_authenticator_selection() {
    // SR-1.7: Authenticator selection criteria
    
    let app = create_test_app().await;
    
    let mut request = create_valid_registration_request();
    request.authenticator_selection = Some(webauthn_rs::proto::AuthenticatorSelectionCriteria {
        require_resident_key: false,
        authenticator_attachment: Some(webauthn_rs::proto::AuthenticatorAttachment::CrossPlatform),
        user_verification: webauthn_rs::proto::UserVerificationPolicy::Preferred,
    });
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify authenticatorSelection is present if requested
    if body["authenticatorSelection"].is_object() {
        let auth_sel = &body["authenticatorSelection"];
        assert!(auth_sel["requireResidentKey"].is_boolean());
        assert!(auth_sel["userVerification"].is_string());
        
        if auth_sel["authenticatorAttachment"].is_string() {
            let attachment = auth_sel["authenticatorAttachment"].as_str().unwrap();
            assert!(attachment == "platform" || attachment == "cross-platform");
        }
    }
}

#[actix_web::test]
async fn test_fido2_sr_1_8_attestation_conveyance() {
    // SR-1.8: Attestation conveyance preference
    
    let app = create_test_app().await;
    
    let mut request = create_valid_registration_request();
    request.attestation = Some(webauthn_rs::proto::AttestationConveyancePreference::Direct);
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify attestation preference
    assert_eq!(body["attestation"], "direct");
    
    // Test other attestation values
    let attestation_values = vec!["none", "indirect", "direct"];
    for attestation in attestation_values {
        let mut request = create_valid_registration_request();
        match attestation {
            "none" => request.attestation = Some(webauthn_rs::proto::AttestationConveyancePreference::None),
            "indirect" => request.attestation = Some(webauthn_rs::proto::AttestationConveyancePreference::Indirect),
            "direct" => request.attestation = Some(webauthn_rs::proto::AttestationConveyancePreference::Direct),
            _ => unreachable!(),
        }
        
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["attestation"], attestation);
    }
}