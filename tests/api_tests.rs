//! API integration tests for FIDO2/WebAuthn endpoints
//! 
//! These tests verify that the API endpoints work correctly according to
//! the FIDO2 conformance test specification.

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;
use webauthn_rp_server::{
    routes::api,
    services::fido::FidoService,
    dto::{
        ServerPublicKeyCredentialCreationOptionsRequest,
        ServerPublicKeyCredentialGetOptionsRequest,
    },
};

#[actix_web::test]
async fn test_attestation_options_success() {
    let fido_service = Arc::new(FidoService::new().unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(fido_service))
            .configure(api::configure)
    ).await;

    let request_body = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert!(body["challenge"].is_string());
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert_eq!(body["rp"]["name"], "Example Corporation");
}

#[actix_web::test]
async fn test_attestation_options_empty_username() {
    let fido_service = Arc::new(FidoService::new().unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(fido_service))
            .configure(api::configure)
    ).await;

    let request_body = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("username"));
}

#[actix_web::test]
async fn test_attestation_result_placeholder() {
    let fido_service = Arc::new(FidoService::new().unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(fido_service))
            .configure(api::configure)
    ).await;

    let request_body = json!({
        "id": "test-credential-id",
        "response": {
            "clientDataJSON": "test-client-data",
            "attestationObject": "test-attestation-object"
        },
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let fido_service = Arc::new(FidoService::new().unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(fido_service))
            .configure(api::configure)
    ).await;

    let request_body = ServerPublicKeyCredentialGetOptionsRequest {
        username: "nonexistent@example.com".to_string(),
        user_verification: None,
        extensions: None,
    };

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("not found"));
}

#[actix_web::test]
async fn test_assertion_result_placeholder() {
    let fido_service = Arc::new(FidoService::new().unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(fido_service))
            .configure(api::configure)
    ).await;

    let request_body = json!({
        "id": "test-credential-id",
        "response": {
            "clientDataJSON": "test-client-data",
            "authenticatorData": "test-auth-data",
            "signature": "test-signature"
        },
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[actix_web::test]
async fn test_fido_conformance_request_format() {
    let fido_service = Arc::new(FidoService::new().unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(fido_service))
            .configure(api::configure)
    ).await;

    // Test the exact request format from FIDO conformance tests
    let request_body = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response format matches FIDO conformance test expectations
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert!(body["rp"].is_object());
    assert!(body["user"].is_object());
    assert!(body["challenge"].is_string());
    assert!(body["pubKeyCredParams"].is_array());
    assert!(body["timeout"].is_number());
    assert!(body["excludeCredentials"].is_array());
    assert!(body["authenticatorSelection"].is_object());
    assert!(body["attestation"].is_string());
    
    // Verify specific field values
    assert_eq!(body["rp"]["name"], "Example Corporation");
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert_eq!(body["attestation"], "direct");
}