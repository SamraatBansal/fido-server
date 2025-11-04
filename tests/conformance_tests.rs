//! Conformance tests for FIDO2/WebAuthn API
//! Tests the exact request/response format from the specification

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;

use fido_server::controllers::WebAuthnController;
use fido_server::webauthn::{WebAuthnConfig, WebAuthnServiceImpl};

#[actix_web::test]
async fn test_registration_flow_exact_spec_format() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test 1: Registration options - exact format from spec
    let registration_request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, registration_request).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure matches spec
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert_eq!(result["rp"]["name"], "Example Corporation");
    assert_eq!(result["user"]["name"], "johndoe@example.com");
    assert_eq!(result["user"]["displayName"], "John Doe");
    assert!(!result["challenge"].as_str().unwrap().is_empty());
    
    // Verify pubKeyCredParams contains ES256 (-7)
    let pub_key_params = result["pubKeyCredParams"].as_array().unwrap();
    assert!(pub_key_params.iter().any(|p| p["alg"] == -7 && p["type"] == "public-key"));
    
    // Verify timeout is present
    assert!(result["timeout"].is_number());
    
    // Verify authenticatorSelection is preserved
    assert_eq!(result["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(result["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
    assert_eq!(result["authenticatorSelection"]["userVerification"], "preferred");
    
    // Verify attestation is preserved
    assert_eq!(result["attestation"], "direct");

    // Test 2: Authentication options - exact format from spec
    let auth_request = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, auth_request).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure matches spec
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert!(!result["challenge"].as_str().unwrap().is_empty());
    assert_eq!(result["rpId"], "localhost");
    assert!(result["timeout"].is_number());
    assert_eq!(result["userVerification"], "required");
}

#[actix_web::test]
async fn test_error_response_format() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test error format for missing username
    let request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "displayName": "John Doe",
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, &request).await;
    assert_eq!(resp.status(), 400);

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify error response format matches spec
    assert_eq!(result["status"], "failed");
    assert!(!result["errorMessage"].as_str().unwrap().is_empty());

    // Test error format for non-existent user
    let request = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&json!({
            "username": "nonexistent@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, &request).await;
    assert_eq!(resp.status(), 400);

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify error response format matches spec
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("User does not exists"));
}