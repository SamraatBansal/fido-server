//! Integration tests for the FIDO2/WebAuthn server

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;

use fido_server::controllers::{WebAuthnController, begin_registration, begin_authentication};
use fido_server::webauthn::{WebAuthnConfig, WebAuthnServiceImpl, WebAuthnService};
use fido_server::webauthn::*;

#[actix_web::test]
async fn test_attestation_options_success() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .route("/webauthn/attestation/options", web::post().to(begin_registration))
    ).await;

    let req = test::TestRequest::post()
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

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
    assert_eq!(result.rp.name, "Example Corporation");
    assert_eq!(result.user.name, "johndoe@example.com");
    assert_eq!(result.user.display_name, "John Doe");
    assert!(!result.challenge.is_empty());
    assert!(!result.pub_key_cred_params.is_empty());
    assert_eq!(result.pub_key_cred_params[0].alg, -7); // ES256
    assert_eq!(result.pub_key_cred_params[1].alg, -257); // RS256
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .route("/webauthn/attestation/options", web::post().to(begin_registration))
    ).await;

    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "",
            "displayName": "John Doe",
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body = test::read_body(resp).await;
    let body_str = String::from_utf8_lossy(&body);
    println!("Response body: '{}'", body_str);
    
    if !body_str.is_empty() {
        let result: ServerResponse = serde_json::from_str(&body_str).unwrap();
        assert_eq!(result.status, "failed");
        assert!(result.error_message.contains("Username is required"));
    }
}

#[actix_web::test]
async fn test_attestation_options_missing_display_name() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .route("/webauthn/attestation/options", web::post().to(begin_registration))
    ).await;

    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "johndoe@example.com",
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Display name is required"));
}

#[actix_web::test]
async fn test_assertion_options_success() {
    // Setup test service and create a user first
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    
    // First, create a user by initiating registration
    let registration_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };
    
    let _reg_result = webauthn_service.begin_registration(registration_request).await.unwrap();

    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .route("/webauthn/assertion/options", web::post().to(begin_authentication))
    ).await;

    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
    assert!(!result.challenge.is_empty());
    assert_eq!(result.rp_id, "localhost");
    assert_eq!(result.user_verification, Some("required".to_string()));
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .route("/webauthn/assertion/options", web::post().to(begin_authentication))
    ).await;

    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&json!({
            "username": "nonexistent@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("User does not exists"));
}

#[actix_web::test]
async fn test_assertion_options_missing_username() {
    // Setup test service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .route("/webauthn/assertion/options", web::post().to(begin_authentication))
    ).await;

    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&json!({
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Username is required"));
}