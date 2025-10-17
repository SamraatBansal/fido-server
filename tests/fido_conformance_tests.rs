//! FIDO Conformance Tests - Tests that match the exact specification format

use actix_web::{test, web, App};
use fido_server::routes::api::configure;
use fido_server::controllers::WebAuthnController;
use fido_server::services::WebAuthnService;
use fido_server::types::*;
use serde_json::json;

#[actix_web::test]
async fn test_fido_conformance_attestation_options_exact_format() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Exact request from FIDO conformance specification
    let req = test::TestRequest::post()
        .uri("/attestation/options")
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

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify exact response format matches FIDO specification
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert_eq!(result["rp"]["name"], "Example Corporation");
    assert_eq!(result["user"]["name"], "johndoe@example.com");
    assert_eq!(result["user"]["displayName"], "John Doe");
    assert!(result["challenge"].as_str().unwrap().len() >= 16); // minimum 16 bytes
    assert!(result["pubKeyCredParams"].as_array().unwrap().len() > 0);
    assert_eq!(result["timeout"], 10000);
    assert_eq!(result["attestation"], "direct");
    assert!(result["authenticatorSelection"].is_object());
}

#[actix_web::test]
async fn test_fido_conformance_attestation_result_invalid_signature() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Test with invalid attestation data
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "invalid-base64",
                "attestationObject": "invalid-base64"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(!result["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_fido_conformance_assertion_options_exact_format() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Exact request from FIDO conformance specification
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify exact response format matches FIDO specification
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert!(result["challenge"].as_str().unwrap().len() >= 16); // minimum 16 bytes
    assert_eq!(result["timeout"], 20000);
    assert_eq!(result["rpId"], "localhost");
    assert_eq!(result["userVerification"], "required");
    assert!(result["allowCredentials"].is_array());
}

#[actix_web::test]
async fn test_fido_conformance_assertion_result_invalid_signature() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Test with invalid assertion data
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "invalid-base64",
                "signature": "invalid-signature",
                "userHandle": "",
                "clientDataJSON": "invalid-base64"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(!result["errorMessage"].as_str().unwrap().is_empty());
}