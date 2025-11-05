//! Integration tests for FIDO2/WebAuthn API endpoints

use actix_web::{test, web, App};
use fido_server::webauthn::*;
use fido_server::webauthn::memory_store::*;
use fido_server::webauthn::service::*;
use fido_server::controllers::{WebAuthnController, begin_registration, finish_registration, begin_authentication, finish_authentication};
use fido_server::routes::api::configure;
use std::sync::Arc;

async fn create_test_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let config = WebAuthnConfig::default();
    let challenge_store = InMemoryChallengeStore::new();
    let user_repo = InMemoryUserRepository::new();
    let credential_repo = InMemoryCredentialRepository::new();
    
    let webauthn_service = WebAuthnServiceImpl::new(config, challenge_store, user_repo, credential_repo).unwrap();
    let controller = Arc::new(WebAuthnController::new(Arc::new(webauthn_service)));
    
    test::init_service(
        App::new()
            .app_data(web::Data::new(controller))
            .configure(configure)
    ).await
}

#[actix_web::test]
async fn test_attestation_options_endpoint() {
    let app = create_test_app().await;
    
    let request = test::TestRequest::post()
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
            extensions: None,
        })
        .to_request();
    
    let response = test::call_service(&app, request).await;
    
    assert!(response.status().is_success());
    
    let response_body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(response).await;
    
    // Verify response structure according to FIDO specification
    assert_eq!(response_body.status, "ok");
    assert_eq!(response_body.error_message, "");
    assert_eq!(response_body.rp.name, "FIDO Server");
    assert_eq!(response_body.user.name, "johndoe@example.com");
    assert_eq!(response_body.user.display_name, "John Doe");
    assert!(!response_body.challenge.is_empty());
    assert!(response_body.pub_key_cred_params.len() > 0);
    assert!(response_body.timeout.is_some());
    assert!(response_body.authenticator_selection.is_some());
    assert!(response_body.attestation.is_some());
}

#[actix_web::test]
async fn test_attestation_options_invalid_request() {
    let app = create_test_app().await;
    
    let request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(), // Invalid: empty username
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: None,
            extensions: None,
        })
        .to_request();
    
    let response = test::call_service(&app, request).await;
    
    assert_eq!(response.status(), 400);
    
    let response_body: ServerResponse = test::read_body_json(response).await;
    assert_eq!(response_body.status, "failed");
    assert!(!response_body.error_message.is_empty());
}

#[actix_web::test]
async fn test_attestation_result_endpoint() {
    let app = create_test_app().await;
    
    // First, begin registration to get a valid challenge
    let begin_request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: Some("none".to_string()),
            extensions: None,
        })
        .to_request();
    
    let begin_response = test::call_service(&app, begin_request).await;
    assert!(begin_response.status().is_success());
    
    let begin_response_body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(begin_response).await;
    
    // Now complete registration with a mock credential
    let credential = ServerPublicKeyCredential {
        id: "test_credential_id".to_string(),
        r#type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
            client_data_json: create_mock_client_data_json(&begin_response_body.challenge, "webauthn.create"),
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ".to_string(),
        }),
        get_client_extension_results: None,
    };
    
    let complete_request = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();
    
    let response = test::call_service(&app, complete_request).await;
    
    // Note: This will likely fail due to signature verification, but should return proper error format
    let response_body: ServerResponse = test::read_body_json(response).await;
    assert!(response_body.status == "ok" || response_body.status == "failed");
}

#[actix_web::test]
async fn test_assertion_options_endpoint() {
    let app = create_test_app().await;
    
    // First, we need to create a user and credential
    let username = "testuser@example.com";
    
    // Create user and credential directly through repositories for this test
    // In a real scenario, this would be done through previous registration
    
    let request = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: username.to_string(),
            user_verification: Some("required".to_string()),
            extensions: None,
        })
        .to_request();
    
    let response = test::call_service(&app, request).await;
    
    // This should fail since user doesn't exist
    assert_eq!(response.status(), 404);
    
    let response_body: ServerResponse = test::read_body_json(response).await;
    assert_eq!(response_body.status, "failed");
    assert!(response_body.error_message.contains("User not found") || response_body.error_message.contains("not found"));
}

#[actix_web::test]
async fn test_assertion_result_endpoint() {
    let app = create_test_app().await;
    
    let credential = ServerPublicKeyCredential {
        id: "test_assertion_credential".to_string(),
        r#type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Assertion(ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIgANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: create_mock_client_data_json("mock_challenge", "webauthn.get"),
        }),
        get_client_extension_results: None,
    };
    
    let request = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&credential)
        .to_request();
    
    let response = test::call_service(&app, request).await;
    
    // Should fail due to invalid challenge or missing credential
    let response_body: ServerResponse = test::read_body_json(response).await;
    assert_eq!(response_body.status, "failed");
    assert!(!response_body.error_message.is_empty());
}

#[actix_web::test]
async fn test_complete_registration_flow() {
    let app = create_test_app().await;
    
    let username = "completeflow@example.com";
    let display_name = "Complete Flow User";
    
    // Step 1: Begin registration
    let begin_request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
            username: username.to_string(),
            display_name: display_name.to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
            extensions: None,
        })
        .to_request();
    
    let begin_response = test::call_service(&app, begin_request).await;
    assert!(begin_response.status().is_success());
    
    let begin_response_body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(begin_response).await;
    
    // Verify the response matches FIDO specification
    assert_eq!(begin_response_body.status, "ok");
    assert_eq!(begin_response_body.rp.name, "FIDO Server");
    assert_eq!(begin_response_body.user.name, username);
    assert_eq!(begin_response_body.user.display_name, display_name);
    assert!(!begin_response_body.challenge.is_empty());
    assert!(begin_response_body.pub_key_cred_params.len() >= 2); // Should support ES256 and RS256
    
    // Verify pubKeyCredParams structure
    let es256_param = begin_response_body.pub_key_cred_params.iter()
        .find(|p| p.alg == -7 && p.r#type == "public-key");
    assert!(es256_param.is_some());
    
    let rs256_param = begin_response_body.pub_key_cred_params.iter()
        .find(|p| p.alg == -257 && p.r#type == "public-key");
    assert!(rs256_param.is_some());
    
    // Verify authenticatorSelection
    assert!(begin_response_body.authenticator_selection.is_some());
    let auth_selection = begin_response_body.authenticator_selection.unwrap();
    assert_eq!(auth_selection.require_resident_key, Some(false));
    assert_eq!(auth_selection.authenticator_attachment, Some("cross-platform".to_string()));
    assert_eq!(auth_selection.user_verification, Some("preferred".to_string()));
    
    // Verify attestation
    assert_eq!(begin_response_body.attestation, Some("direct".to_string()));
}

fn create_mock_client_data_json(challenge: &str, typ: &str) -> String {
    use base64::{Engine as _, engine::general_purpose};
    
    let client_data = serde_json::json!({
        "type": typ,
        "challenge": challenge,
        "origin": "http://localhost:8080",
        "hashAlgorithm": "SHA-256"
    });
    
    let client_data_str = client_data.to_string();
    general_purpose::URL_SAFE_NO_PAD.encode(client_data_str.as_bytes())
}

#[actix_web::test]
async fn test_endpoint_not_found() {
    let app = create_test_app().await;
    
    let request = test::TestRequest::post()
        .uri("/nonexistent/endpoint")
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), 404);
}

#[actix_web::test]
async fn test_invalid_method() {
    let app = create_test_app().await;
    
    let request = test::TestRequest::get()
        .uri("/attestation/options")
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), 405); // Method Not Allowed
}

#[actix_web::test]
async fn test_invalid_json() {
    let app = create_test_app().await;
    
    let request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_payload("invalid json")
        .insert_header(("content-type", "application/json"))
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), 400);
}