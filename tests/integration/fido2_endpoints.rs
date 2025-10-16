//! Integration tests for FIDO2/WebAuthn endpoints

use actix_web::{test, App, http::StatusCode};
use fido_server::{routes::api::configure, services::{WebAuthnService, WebAuthnConfig}};
use serde_json::json;
use std::sync::Arc;

/// Helper function to create test app
async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnService::new(webauthn_config).unwrap());

    test::init_service(
        App::new()
            .configure(configure)
            .app_data(actix_web::web::Data::new(webauthn_service))
    ).await
}

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = create_test_app().await;

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
    let app = create_test_app().await;

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
async fn test_attestation_options_missing_fields() {
    let app = create_test_app().await;

    // Test with missing required fields
    let request_payload = json!({
        "displayName": "John Doe"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = create_test_app().await;

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

    let client_data_json_b64 = base64::encode_config(
        serde_json::to_string(&client_data_json).unwrap(),
        base64::URL_SAFE_NO_PAD,
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
async fn test_attestation_result_invalid_challenge() {
    let app = create_test_app().await;

    let attestation_request = json!({
        "id": "test-credential-id",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJpbnZhbGlkLWNoYWxsZW5nZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZg3liA6MaHQ0Fw9kdmBbj-SuuaKMsMeZXPO6gx2XgwEAAAAA"
        },
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(response_body["status"], "failed");
    assert!(!response_body["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = create_test_app().await;

    // First, register a user and credential
    let registration_request = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "attestation": "direct"
    });

    let reg_req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_request)
        .to_request();

    let reg_resp = test::call_service(&app, reg_req).await;
    assert_eq!(reg_resp.status(), StatusCode::OK);

    let reg_response: serde_json::Value = test::read_body_json(reg_resp).await;
    let challenge = reg_response["challenge"].as_str().unwrap();

    // Complete registration with mock credential
    let client_data_json = json!({
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "type": "webauthn.create"
    });

    let client_data_json_b64 = base64::encode_config(
        serde_json::to_string(&client_data_json).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );

    let attestation_request = json!({
        "id": "test-credential-id",
        "response": {
            "clientDataJSON": client_data_json_b64,
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZg3liA6MaHQ0Fw9kdmBbj-SuuaKMsMeZXPO6gx2XgwEAAAAA"
        },
        "type": "public-key"
    });

    let att_req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_request)
        .to_request();

    let att_resp = test::call_service(&app, att_req).await;
    assert_eq!(att_resp.status(), StatusCode::OK);

    // Now test assertion options
    let assertion_request = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure matches FIDO2 specification
    assert_eq!(response_body["status"], "ok");
    assert_eq!(response_body["errorMessage"], "");
    assert!(response_body["challenge"].is_string());
    assert!(response_body["timeout"].is_number());
    assert!(response_body["rpId"].is_string());
    assert!(response_body["allowCredentials"].is_array());
    assert_eq!(response_body["userVerification"], "required");
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = create_test_app().await;

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
async fn test_assertion_result_success() {
    let app = create_test_app().await;

    // First, register a user and credential
    let registration_request = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "attestation": "direct"
    });

    let reg_req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_request)
        .to_request();

    let reg_resp = test::call_service(&app, reg_req).await;
    assert_eq!(reg_resp.status(), StatusCode::OK);

    let reg_response: serde_json::Value = test::read_body_json(reg_resp).await;
    let challenge = reg_response["challenge"].as_str().unwrap();

    // Complete registration
    let client_data_json = json!({
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "type": "webauthn.create"
    });

    let client_data_json_b64 = base64::encode_config(
        serde_json::to_string(&client_data_json).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );

    let attestation_request = json!({
        "id": "dGVzdC1jcmVkZW50aWFsLWlk", // base64 of "test-credential-id"
        "response": {
            "clientDataJSON": client_data_json_b64,
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZg3liA6MaHQ0Fw9kdmBbj-SuuaKMsMeZXPO6gx2XgwEAAAAA"
        },
        "type": "public-key"
    });

    let att_req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_request)
        .to_request();

    let att_resp = test::call_service(&app, att_req).await;
    assert_eq!(att_resp.status(), StatusCode::OK);

    // Get assertion challenge
    let assertion_request = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let assert_req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let assert_resp = test::call_service(&app, assert_req).await;
    assert_eq!(assert_resp.status(), StatusCode::OK);

    let assert_response: serde_json::Value = test::read_body_json(assert_resp).await;
    let assertion_challenge = assert_response["challenge"].as_str().unwrap();

    // Create mock assertion response
    let assertion_client_data = json!({
        "challenge": assertion_challenge,
        "origin": "http://localhost:3000",
        "type": "webauthn.get"
    });

    let assertion_client_data_b64 = base64::encode_config(
        serde_json::to_string(&assertion_client_data).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );

    let assertion_verification_request = json!({
        "id": "dGVzdC1jcmVkZW50aWFsLWlk",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": assertion_client_data_b64
        },
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion_verification_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(response_body["status"], "ok");
    assert_eq!(response_body["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_invalid_credential() {
    let app = create_test_app().await;

    let assertion_request = json!({
        "id": "nonexistent-credential-id",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0LWNoYWxsZW5nZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ"
        },
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let response_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(response_body["status"], "failed");
    assert!(!response_body["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_endpoint_not_found() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/nonexistent-endpoint")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn test_method_not_allowed() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/attestation/options")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}