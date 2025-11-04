//! Integration tests for attestation and assertion result endpoints

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;
use base64::Engine;

use fido_server::controllers::WebAuthnController;
use fido_server::webauthn::{WebAuthnConfig, WebAuthnServiceImpl, WebAuthnService};
use fido_server::webauthn::*;

#[actix_web::test]
async fn test_attestation_result_success() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // First, initiate registration to get a challenge
    let registration_request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "none"
        }))
        .to_request();

    let resp = test::call_service(&app, registration_request).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    let challenge = result["challenge"].as_str().unwrap();

    // Create a mock credential with the challenge
    let client_data_json = json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "crossOrigin": false
    });

    let credential_request = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data_json.to_string().as_bytes()),
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, credential_request).await;
    assert!(resp.status().is_success());

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
}

#[actix_web::test]
async fn test_attestation_result_missing_id() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with missing id field
    let credential_request = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&json!({
            "type": "public-key",
            "response": {
                "clientDataJSON": "invalid",
                "attestationObject": "invalid"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, credential_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Credential ID is required"));
}

#[actix_web::test]
async fn test_attestation_result_invalid_type() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with invalid credential type
    let credential_request = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "invalid-type",
            "response": {
                "clientDataJSON": "invalid",
                "attestationObject": "invalid"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, credential_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Invalid credential type"));
}

#[actix_web::test]
async fn test_attestation_result_missing_client_data() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with missing client data JSON
    let credential_request = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "public-key",
            "response": {
                "attestationObject": "invalid"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, credential_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Client data JSON is required"));
}

#[actix_web::test]
async fn test_attestation_result_missing_attestation_object() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with missing attestation object
    let credential_request = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": "invalid"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, credential_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Attestation object is required"));
}

#[actix_web::test]
async fn test_assertion_result_success() {
    // Setup test service and create a user first
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    
    // First, create a user by initiating registration
    let registration_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };
    
    let _reg_result = webauthn_service.begin_registration(registration_request).await.unwrap();

    // Simulate storing a credential
    let credential = Credential {
        id: "test_credential_id".to_string(),
        user_id: "user_id".to_string(),
        public_key: vec![1, 2, 3, 4],
        sign_count: 0,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    };
    webauthn_service.store_credential(credential).await.unwrap();

    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // First, initiate authentication to get a challenge
    let auth_request = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&json!({
            "username": "test@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, auth_request).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    let challenge = result["challenge"].as_str().unwrap();

    // Create a mock assertion with the challenge
    let client_data_json = json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "crossOrigin": false
    });

    let assertion_request = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data_json.to_string().as_bytes()),
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEUCIQCdBSXqMyV_3q4k6oXJvBXXj9qU-8pLpXsJk8wJxWQIgYzq2i3m5vW6X7A8bKxK9Z4Y2X7A8bKxK9Z4Y2X7A8bKxK9Z4Y2X7A8bKxK9Z4Y2X7A",
                "userHandle": ""
            }
        }))
        .to_request();

    let resp = test::call_service(&app, assertion_request).await;
    assert!(resp.status().is_success());

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
}

#[actix_web::test]
async fn test_assertion_result_missing_id() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with missing id field
    let assertion_request = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&json!({
            "type": "public-key",
            "response": {
                "clientDataJSON": "invalid",
                "authenticatorData": "invalid",
                "signature": "invalid",
                "userHandle": ""
            }
        }))
        .to_request();

    let resp = test::call_service(&app, assertion_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Credential ID is required"));
}

#[actix_web::test]
async fn test_assertion_result_missing_authenticator_data() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with missing authenticator data
    let assertion_request = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": "invalid",
                "signature": "invalid",
                "userHandle": ""
            }
        }))
        .to_request();

    let resp = test::call_service(&app, assertion_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Authenticator data is required"));
}

#[actix_web::test]
async fn test_assertion_result_missing_signature() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with missing signature
    let assertion_request = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&json!({
            "id": "test_credential_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": "invalid",
                "authenticatorData": "invalid",
                "userHandle": ""
            }
        }))
        .to_request();

    let resp = test::call_service(&app, assertion_request).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Signature is required"));
}