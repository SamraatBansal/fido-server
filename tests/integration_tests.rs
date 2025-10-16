//! Integration tests for FIDO2/WebAuthn server

use actix_web::{test, App, web::Data};
use fido_server::routes::api::configure;
use fido_server::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredential,
    ServerAuthenticatorAttestationResponse,
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialAssertion,
    ServerAuthenticatorAssertionResponse,
    AuthenticatorSelectionCriteria,
};
use fido_server::services::{WebAuthnService, WebAuthnConfig};
use std::sync::Arc;

async fn create_test_app() -> impl actix_web::dev::Service<
    actix_http::requests::request::Request,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let webauthn_service = Arc::new(
        WebAuthnService::new(WebAuthnConfig::default())
            .expect("Failed to create WebAuthn service")
    );
    
    test::init_service(
        App::new()
            .app_data(Data::new(webauthn_service))
            .configure(configure)
    ).await
}

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = create_test_app().await;

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
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert_eq!(body["rp"]["name"], "FIDO Server");
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    assert_eq!(body["pubKeyCredParams"][0]["type"], "public-key");
    assert_eq!(body["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(body["timeout"], 60000);
    assert_eq!(body["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_default_values() {
    let app = create_test_app().await;

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
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["attestation"], "none");
    if let Some(exclude_creds) = body["excludeCredentials"].as_array() {
        assert!(exclude_creds.is_empty());
    }
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            },
            get_client_extension_results: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
}

#[actix_web::test]
async fn test_attestation_result_missing_credential_id() {
    let app = create_test_app().await;

    let credential = ServerPublicKeyCredential {
        id: "".to_string(), // Empty ID should cause error
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&credential)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    let error_msg = body["errorMessage"].as_str().unwrap_or("");
    assert!(!error_msg.is_empty());
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "johndoe@example.com".to_string(),
            user_verification: Some("required".to_string()),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    assert_eq!(body["rpId"], "localhost");
    assert_eq!(body["userVerification"], "required");
    assert!(body["allowCredentials"].is_array());
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = create_test_app().await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&ServerPublicKeyCredentialAssertion {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: Some("".to_string()),
                client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            },
            get_client_extension_results: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_missing_credential_id() {
    let app = create_test_app().await;

    let assertion = ServerPublicKeyCredentialAssertion {
        id: "".to_string(), // Empty ID should cause error
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    let error_msg = body["errorMessage"].as_str().unwrap_or("");
    assert!(!error_msg.is_empty());
}