//! Integration tests for FIDO2/WebAuthn endpoints

use actix_web::{test, web, App};
use fido_server::routes::api::configure;
use fido_server::domain::models::*;

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
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
    
    let body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(body.base.status, "ok");
    assert_eq!(body.rp.name, "Example Corporation");
    assert_eq!(body.user.name, "johndoe@example.com");
    assert_eq!(body.user.display_name, "John Doe");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.pub_key_cred_params.len(), 1);
    assert_eq!(body.pub_key_cred_params[0].alg, -7);
    assert_eq!(body.pub_key_cred_params[0].r#type, "public-key");
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test_credential_id".to_string(),
            r#type: "public-key".to_string(),
            response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
                client_data_json: "eyJ0eXN0Ijoid2ViYXV0aG4uY3JlYXRlIn0=".to_string(),
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ".to_string(),
            }),
            get_client_extension_results: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "nonexistent@example.com".to_string(),
            user_verification: Some("required".to_string()),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&ServerPublicKeyCredential {
            id: "test_credential_id".to_string(),
            r#type: "public-key".to_string(),
            response: ServerAuthenticatorResponse::Assertion(ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: "".to_string(),
                client_data_json: "eyJ0eXN0Ijoid2ViYXV0aG4uZ2V0In0=".to_string(),
            }),
            get_client_extension_results: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
    
    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}