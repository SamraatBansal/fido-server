//! Integration tests for FIDO2/WebAuthn endpoints

use actix_web::{test, web, App};
use fido_server::routes::api::configure;
use fido_server::controllers::WebAuthnController;
use fido_server::services::WebAuthnService;
use fido_server::types::*;

#[actix_web::test]
async fn test_attestation_options_success() {
    // Initialize WebAuthn service and controller
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

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        })
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
    assert_eq!(result.pub_key_cred_params.len(), 2); // ES256 and RS256
    assert_eq!(result.timeout, 10000);
    assert_eq!(result.attestation, "direct");
}

#[actix_web::test]
async fn test_attestation_options_defaults() {
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

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.attestation, "none"); // default value
    assert!(result.authenticator_selection.is_some());
}

#[actix_web::test]
async fn test_assertion_options_success() {
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

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "johndoe@example.com".to_string(),
            user_verification: Some("required".to_string()),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
    assert!(!result.challenge.is_empty());
    assert_eq!(result.timeout, 20000);
    assert_eq!(result.rp_id, "localhost");
    assert_eq!(result.user_verification, "required");
}

#[actix_web::test]
async fn test_attestation_result_invalid_response() {
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

    // Send invalid response (missing required fields)
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&serde_json::json!({
            "id": "test-id",
            "type": "public-key",
            "response": {
                "invalid": "response"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_assertion_result_invalid_response() {
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

    // Send invalid response (missing required fields)
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&serde_json::json!({
            "id": "test-id",
            "type": "public-key",
            "response": {
                "invalid": "response"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());
}