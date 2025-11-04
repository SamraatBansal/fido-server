//! Integration tests for FIDO2/WebAuthn API endpoints
//! 
//! These tests validate the complete registration and authentication flows
//! according to the FIDO Alliance specification.

use actix_web::{test, web, App};
use fido_server::controllers::webauthn::WebAuthnController;
use fido_server::services::ServiceFactory;
use fido_server::config::Settings;
use fido_server::webauthn::*;
use std::sync::Arc;
use base64::Engine;

/// Create test app with WebAuthn controller
async fn create_test_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let settings = Settings::new().expect("Failed to create test settings");
    let webauthn_service = ServiceFactory::create_webauthn_service(&settings)
        .await
        .expect("Failed to create WebAuthn service");
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    App::new()
        .app_data(web::Data::new(controller))
        .configure(fido_server::routes::api::configure)
}

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: "direct".to_string(),
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
    assert!(!result.pub_key_cred_params.is_empty());
    assert_eq!(result.pub_key_cred_params[0].alg, -7); // ES256
    assert_eq!(result.pub_key_cred_params[1].alg, -257); // RS256
    assert_eq!(result.pub_key_cred_params[2].alg, -8); // Ed25519
    assert!(result.timeout.is_some());
    assert_eq!(result.attestation, Some("direct".to_string()));
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: "none".to_string(),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Username is required"));
}

#[actix_web::test]
async fn test_attestation_options_missing_display_name() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "".to_string(),
            authenticator_selection: None,
            attestation: "none".to_string(),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Display name is required"));
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = create_test_app().await;

    // First, begin registration to get a challenge
    let begin_req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: "none".to_string(),
        })
        .to_request();

    let begin_resp = test::call_service(&app, begin_req).await;
    assert!(begin_resp.status().is_success());

    let begin_result: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(begin_resp).await;
    let challenge = begin_result.challenge.clone();

    // Create mock client data JSON with the challenge
    let client_data = serde_json::json!({
        "challenge": challenge,
        "type": "webauthn.create",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });

    let client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&client_data).unwrap());

    // Create mock attestation object
    let attestation_object = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQAAAAAAAAAAAAAAAAAAAAAAJGNivmk3aQAAAAAjalZ3iQj8AYKvB1AYW1vYm9hdAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wAB".to_string();

    // Complete registration
    let complete_req = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test_credential_id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json,
                attestation_object,
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let complete_resp = test::call_service(&app, complete_req).await;
    assert!(complete_resp.status().is_success());

    let result: ServerResponse = test::read_body_json(complete_resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
}

#[actix_web::test]
async fn test_attestation_result_invalid_credential_type() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test_credential_id".to_string(),
            cred_type: "invalid-type".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: "invalid".to_string(),
                attestation_object: "invalid".to_string(),
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Invalid credential type"));
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = create_test_app().await;

    // First register a user
    let register_req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: "none".to_string(),
        })
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Now test assertion options
    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
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
    assert_eq!(result.rp_id, "localhost");
    assert!(result.timeout.is_some());
    assert_eq!(result.user_verification, Some("required".to_string()));
}

#[actix_web::test]
async fn test_assertion_options_user_not_exists() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "nonexistent@example.com".to_string(),
            user_verification: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("User does not exists!"));
}

#[actix_web::test]
async fn test_assertion_options_missing_username() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "".to_string(),
            user_verification: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Username is required"));
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = create_test_app().await;

    // First register a user and credential
    let register_req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: "none".to_string(),
        })
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    let register_result: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(register_resp).await;
    let challenge = register_result.challenge.clone();

    // Complete registration
    let client_data = serde_json::json!({
        "challenge": challenge,
        "type": "webauthn.create",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });

    let client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&client_data).unwrap());

    let complete_reg_req = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test_credential_id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json,
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQAAAAAAAAAAAAAAAAAAAAAAJGNivmk3aQAAAAAjalZ3iQj8AYKvB1AYW1vYm9hdAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wAB".to_string(),
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let complete_reg_resp = test::call_service(&app, complete_reg_req).await;
    assert!(complete_reg_resp.status().is_success());

    // Now begin authentication
    let auth_begin_req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "johndoe@example.com".to_string(),
            user_verification: None,
        })
        .to_request();

    let auth_begin_resp = test::call_service(&app, auth_begin_req).await;
    assert!(auth_begin_resp.status().is_success());

    let auth_begin_result: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(auth_begin_resp).await;
    let auth_challenge = auth_begin_result.challenge.clone();

    // Create mock assertion
    let auth_client_data = serde_json::json!({
        "challenge": auth_challenge,
        "type": "webauthn.get",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });

    let auth_client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&auth_client_data).unwrap());

    // Complete authentication
    let auth_complete_req = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&ServerAssertionPublicKeyCredential {
            id: "test_credential_id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEUCIQCdBCNL4soW_2y2n1x8rXx9n8Q9o7t3z3x3x3x3x3x3x3x3x3x3x3x3x3x3x3x3x".to_string(),
                user_handle: "".to_string(),
                client_data_json: auth_client_data_json,
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let auth_complete_resp = test::call_service(&app, auth_complete_req).await;
    assert!(auth_complete_resp.status().is_success());

    let result: ServerResponse = test::read_body_json(auth_complete_resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
}

#[actix_web::test]
async fn test_assertion_result_invalid_credential_type() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&ServerAssertionPublicKeyCredential {
            id: "test_credential_id".to_string(),
            cred_type: "invalid-type".to_string(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "invalid".to_string(),
                signature: "invalid".to_string(),
                user_handle: "".to_string(),
                client_data_json: "invalid".to_string(),
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let result: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result.status, "failed");
    assert!(result.error_message.contains("Invalid credential type"));
}

#[actix_web::test]
async fn test_complete_registration_flow() {
    let app = create_test_app().await;

    // Step 1: Begin registration
    let begin_req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "completeflow@example.com".to_string(),
            display_name: "Complete Flow User".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: "direct".to_string(),
        })
        .to_request();

    let begin_resp = test::call_service(&app, begin_req).await;
    assert!(begin_resp.status().is_success());

    let begin_result: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(begin_resp).await;
    assert_eq!(begin_result.status, "ok");
    assert_eq!(begin_result.user.name, "completeflow@example.com");
    assert_eq!(begin_result.user.display_name, "Complete Flow User");
    assert_eq!(begin_result.authenticator_selection.as_ref().unwrap().authenticator_attachment.as_ref().unwrap(), "cross-platform");
    assert_eq!(begin_result.attestation, Some("direct".to_string()));

    // Step 2: Complete registration
    let challenge = begin_result.challenge.clone();
    let client_data = serde_json::json!({
        "challenge": challenge,
        "type": "webauthn.create",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });

    let client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&client_data).unwrap());

    let complete_req = test::TestRequest::post()
        .uri("/webauthn/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "complete_flow_credential_id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json,
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQAAAAAAAAAAAAAAAAAAAAAAJGNivmk3aQAAAAAjalZ3iQj8AYKvB1AYW1vYm9hdAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wAB".to_string(),
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let complete_resp = test::call_service(&app, complete_req).await;
    assert!(complete_resp.status().is_success());

    let complete_result: ServerResponse = test::read_body_json(complete_resp).await;
    assert_eq!(complete_result.status, "ok");

    // Step 3: Begin authentication
    let auth_begin_req = test::TestRequest::post()
        .uri("/webauthn/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "completeflow@example.com".to_string(),
            user_verification: Some("required".to_string()),
        })
        .to_request();

    let auth_begin_resp = test::call_service(&app, auth_begin_req).await;
    assert!(auth_begin_resp.status().is_success());

    let auth_begin_result: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(auth_begin_resp).await;
    assert_eq!(auth_begin_result.status, "ok");
    assert_eq!(auth_begin_result.user_verification, Some("required".to_string()));
    assert!(!auth_begin_result.allow_credentials.is_empty());

    // Step 4: Complete authentication
    let auth_challenge = auth_begin_result.challenge.clone();
    let auth_client_data = serde_json::json!({
        "challenge": auth_challenge,
        "type": "webauthn.get",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });

    let auth_client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&auth_client_data).unwrap());

    let auth_complete_req = test::TestRequest::post()
        .uri("/webauthn/assertion/result")
        .set_json(&ServerAssertionPublicKeyCredential {
            id: "complete_flow_credential_id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEUCIQCdBCNL4soW_2y2n1x8rXx9n8Q9o7t3z3x3x3x3x3x3x3x3x3x3x3x3x3x3x3x".to_string(),
                user_handle: "".to_string(),
                client_data_json: auth_client_data_json,
            },
            get_client_extension_results: std::collections::HashMap::new(),
        })
        .to_request();

    let auth_complete_resp = test::call_service(&app, auth_complete_req).await;
    assert!(auth_complete_resp.status().is_success());

    let auth_complete_result: ServerResponse = test::read_body_json(auth_complete_resp).await;
    assert_eq!(auth_complete_result.status, "ok");
    assert_eq!(auth_complete_result.error_message, "");
}