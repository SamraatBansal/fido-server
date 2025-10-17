//! Integration tests for FIDO2 WebAuthn API

use actix_web::{test, web, App};
use fido_server::controllers::webauthn_controller::*;
use fido_server::models::webauthn::*;
use fido_server::services::webauthn_service::WebAuthnService;
use fido_server::utils::testing::*;
use std::sync::Arc;

#[actix_web::test]
async fn test_attestation_options_success() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&create_test_registration_request())
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let response: ServerPublicKeyCredentialCreationOptionsResponse = 
        test::read_body_json(resp).await;
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
    assert_eq!(response.rp.name, "Example Corporation");
    assert_eq!(response.user.name, "johndoe@example.com");
    assert_eq!(response.user.display_name, "John Doe");
    assert!(!response.challenge.is_empty());
    assert!(!response.pub_key_cred_params.is_empty());
    assert!(response.timeout.is_some());
    assert_eq!(response.attestation, Some("direct".to_string()));
}

#[actix_web::test]
async fn test_attestation_options_minimal_request() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let minimal_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
    };
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&minimal_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let response: ServerPublicKeyCredentialCreationOptionsResponse = 
        test::read_body_json(resp).await;
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.user.name, "test@example.com");
    assert_eq!(response.user.display_name, "Test User");
    assert_eq!(response.attestation, Some("none".to_string()));
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&create_mock_attestation_credential())
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let response: ServerResponse = test::read_body_json(resp).await;
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
}

#[actix_web::test]
async fn test_attestation_result_missing_id() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let mut credential = create_mock_attestation_credential();
    credential.id = "".to_string();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_client_error());
    
    let response: ServerResponse = test::read_body_json(resp).await;
    
    assert_eq!(response.status, "failed");
    assert!(response.error_message.contains("Missing credential ID"));
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&create_test_authentication_request())
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let response: ServerPublicKeyCredentialGetOptionsResponse = 
        test::read_body_json(resp).await;
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
    assert!(!response.challenge.is_empty());
    assert_eq!(response.rp_id, "localhost");
    assert!(response.timeout.is_some());
    assert_eq!(response.user_verification, Some("required".to_string()));
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&create_mock_assertion_credential())
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let response: ServerResponse = test::read_body_json(resp).await;
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
}

#[actix_web::test]
async fn test_assertion_result_missing_id() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    let mut credential = create_mock_assertion_credential();
    credential.id = "".to_string();
    
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&credential)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_client_error());
    
    let response: ServerResponse = test::read_body_json(resp).await;
    
    assert_eq!(response.status, "failed");
    assert!(response.error_message.contains("Missing credential ID"));
}

#[actix_web::test]
async fn test_registration_flow_complete() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    // Step 1: Get registration challenge
    let registration_req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&create_test_registration_request())
        .to_request();

    let registration_resp = test::call_service(&app, registration_req).await;
    assert!(registration_resp.status().is_success());
    
    let _registration_response: ServerPublicKeyCredentialCreationOptionsResponse = 
        test::read_body_json(registration_resp).await;
    
    // Step 2: Complete registration
    let credential = create_mock_attestation_credential();
    let completion_req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();

    let completion_resp = test::call_service(&app, completion_req).await;
    assert!(completion_resp.status().is_success());
    
    let completion_response: ServerResponse = test::read_body_json(completion_resp).await;
    assert_eq!(completion_response.status, "ok");
}

#[actix_web::test]
async fn test_authentication_flow_complete() {
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .service(registration_challenge)
            .service(registration_result)
            .service(authentication_challenge)
            .service(authentication_result)
    ).await;
    
    // Step 1: Get authentication challenge
    let auth_req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&create_test_authentication_request())
        .to_request();

    let auth_resp = test::call_service(&app, auth_req).await;
    assert!(auth_resp.status().is_success());
    
    let _auth_response: ServerPublicKeyCredentialGetOptionsResponse = 
        test::read_body_json(auth_resp).await;
    
    // Step 2: Complete authentication
    let credential = create_mock_assertion_credential();
    let assertion_req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&credential)
        .to_request();

    let assertion_resp = test::call_service(&app, assertion_req).await;
    assert!(assertion_resp.status().is_success());
    
    let assertion_response: ServerResponse = test::read_body_json(assertion_resp).await;
    assert_eq!(assertion_response.status, "ok");
}