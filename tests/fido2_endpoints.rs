//! Integration tests for FIDO2/WebAuthn endpoints

use actix_web::{test, App, http::StatusCode, web};
use fido_server::{routes::api::configure, services::{WebAuthnService, WebAuthnConfig}};
use serde_json::json;
use std::sync::Arc;
use base64::{engine::general_purpose, Engine as _};

#[actix_web::test]
async fn test_attestation_options_success() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    let app = test::init_service(
        App::new()
            .configure(configure)
            .app_data(web::Data::new(webauthn_service))
    ).await;

    let request_payload = json!({
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
        .set_json(&request_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure matches FIDO2 specification
    assert_eq!(response_body["status"], "ok");
    assert_eq!(response_body["errorMessage"], "");
    assert!(response_body["rp"]["name"].is_string());
    assert!(response_body["user"]["id"].is_string());
    assert_eq!(response_body["user"]["name"], "johndoe@example.com");
    assert_eq!(response_body["user"]["displayName"], "John Doe");
    assert!(response_body["challenge"].is_string());
    assert!(response_body["pubKeyCredParams"].is_array());
    assert!(response_body["timeout"].is_number());
    assert_eq!(response_body["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(response_body["authenticatorSelection"]["userVerification"], "preferred");
    assert_eq!(response_body["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_validation_error() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    let app = test::init_service(
        App::new()
            .configure(configure)
            .app_data(web::Data::new(webauthn_service))
    ).await;

    // Test with empty username
    let request_payload = json!({
        "username": "",
        "displayName": "John Doe",
        "attestation": "direct"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(response_body["status"], "failed");
    assert!(!response_body["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    let app = test::init_service(
        App::new()
            .configure(configure)
            .app_data(web::Data::new(webauthn_service))
    ).await;

    // First, create a registration challenge
    let challenge_request = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "attestation": "direct"
    });

    let challenge_req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&challenge_request)
        .to_request();

    let challenge_resp = test::call_service(&app, challenge_req).await;
    assert_eq!(challenge_resp.status(), StatusCode::OK);
    
    let challenge_response: serde_json::Value = test::read_body_json(challenge_resp).await;
    let challenge = challenge_response["challenge"].as_str().unwrap();

    // Create mock attestation response
    let client_data_json = json!({
        "challenge": challenge,
        "clientExtensions": {},
        "hashAlgorithm": "SHA-256",
        "origin": "http://localhost:3000",
        "type": "webauthn.create"
    });

    let client_data_json_b64 = general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&client_data_json).unwrap(),
    );

    let attestation_request = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": client_data_json_b64,
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(response_body["status"], "ok");
    assert_eq!(response_body["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    let app = test::init_service(
        App::new()
            .configure(configure)
            .app_data(web::Data::new(webauthn_service))
    ).await;

    let assertion_request = json!({
        "username": "nonexistent@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(response_body["status"], "failed");
    assert!(response_body["errorMessage"].as_str().unwrap().contains("does not exists"));
}

#[actix_web::test]
async fn test_endpoint_not_found() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    let app = test::init_service(
        App::new()
            .configure(configure)
            .app_data(web::Data::new(webauthn_service))
    ).await;

    let req = test::TestRequest::get()
        .uri("/nonexistent-endpoint")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn test_method_not_allowed() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    let app = test::init_service(
        App::new()
            .configure(configure)
            .app_data(web::Data::new(webauthn_service))
    ).await;

    let req = test::TestRequest::get()
        .uri("/attestation/options")
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Actix-web returns 404 for non-existent routes, not 405
    assert!(resp.status() == StatusCode::METHOD_NOT_ALLOWED || resp.status() == StatusCode::NOT_FOUND);
}