//! Basic tests for FIDO server data structures

use fido_server::dto::*;
use serde_json::json;

#[test]
fn test_server_response_format() {
    // Test that ServerResponse matches the expected format
    let success = ServerResponse::ok();
    assert_eq!(success.status, "ok");
    assert_eq!(success.error_message, "");

    let failure = ServerResponse::failed("Test error message");
    assert_eq!(failure.status, "failed");
    assert_eq!(failure.error_message, "Test error message");

    // Test JSON serialization
    let success_json = serde_json::to_value(&success).unwrap();
    assert_eq!(success_json["status"], "ok");
    assert_eq!(success_json["errorMessage"], "");

    let failure_json = serde_json::to_value(&failure).unwrap();
    assert_eq!(failure_json["status"], "failed");
    assert_eq!(failure_json["errorMessage"], "Test error message");

    println!("✓ Server response format test passed");
}

#[test]
fn test_registration_request_structure() {
    // Test that our data structures can be serialized/deserialized properly
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: webauthn_rs_proto::AttestationConveyancePreference::None,
    };

    let json_str = serde_json::to_string(&request).unwrap();
    let parsed: ServerPublicKeyCredentialCreationOptionsRequest = serde_json::from_str(&json_str).unwrap();
    
    assert_eq!(parsed.username, "test@example.com");
    assert_eq!(parsed.display_name, "Test User");
    
    println!("✓ Registration request structure test passed");
    println!("  - Serialized: {}", json_str);
}

#[test]
fn test_registration_response_structure() {
    // Test that we can create and serialize a registration response
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        server_response: ServerResponse::ok(),
        rp: fido_server::dto::registration::PublicKeyCredentialRpEntity {
            id: Some("localhost".to_string()),
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: "U3932ee31vKEC0JtJMIQ".to_string(),
            name: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
        },
        challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        pub_key_cred_params: vec![
            fido_server::dto::registration::PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7,
            }
        ],
        timeout: Some(10000),
        exclude_credentials: vec![],
        authenticator_selection: None,
        attestation: webauthn_rs_proto::AttestationConveyancePreference::Direct,
        extensions: None,
    };

    let json_str = serde_json::to_string(&response).unwrap();
    let parsed: ServerPublicKeyCredentialCreationOptionsResponse = serde_json::from_str(&json_str).unwrap();
    
    assert_eq!(parsed.server_response.status, "ok");
    assert_eq!(parsed.rp.name, "Example Corporation");
    assert_eq!(parsed.user.name, "johndoe@example.com");
    assert_eq!(parsed.challenge, "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN");
    assert_eq!(parsed.pub_key_cred_params.len(), 1);
    assert_eq!(parsed.pub_key_cred_params[0].alg, -7);
    assert_eq!(parsed.timeout, Some(10000));
    
    println!("✓ Registration response structure test passed");
}

#[test]
fn test_authentication_request_structure() {
    let request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "johndoe@example.com".to_string(),
        user_verification: Some(webauthn_rs_proto::UserVerificationPolicy::Required),
    };

    let json_str = serde_json::to_string(&request).unwrap();
    let parsed: ServerPublicKeyCredentialGetOptionsRequest = serde_json::from_str(&json_str).unwrap();
    
    assert_eq!(parsed.username, "johndoe@example.com");
    assert!(parsed.user_verification.is_some());
    
    println!("✓ Authentication request structure test passed");
}

#[test]
fn test_authentication_response_structure() {
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        server_response: ServerResponse::ok(),
        challenge: "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
        timeout: Some(20000),
        rp_id: Some("localhost".to_string()),
        allow_credentials: vec![],
        user_verification: Some(webauthn_rs_proto::UserVerificationPolicy::Required),
        extensions: None,
    };

    let json_str = serde_json::to_string(&response).unwrap();
    let parsed: ServerPublicKeyCredentialGetOptionsResponse = serde_json::from_str(&json_str).unwrap();
    
    assert_eq!(parsed.server_response.status, "ok");
    assert_eq!(parsed.challenge, "6283u0svT-YIF3pSolzkQHStwkJCaLKx");
    assert_eq!(parsed.timeout, Some(20000));
    assert_eq!(parsed.rp_id, Some("localhost".to_string()));
    
    println!("✓ Authentication response structure test passed");
}

#[test]
fn test_fido_conformance_json_format() {
    // Test that we can parse the exact JSON format from FIDO conformance tests
    let fido_request_json = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let parsed: ServerPublicKeyCredentialCreationOptionsRequest = 
        serde_json::from_value(fido_request_json).unwrap();
    
    assert_eq!(parsed.username, "johndoe@example.com");
    assert_eq!(parsed.display_name, "John Doe");
    
    println!("✓ FIDO conformance JSON format test passed");
}