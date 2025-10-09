//! Standalone integration test to verify basic functionality

use actix_web::{test, App, http::StatusCode};
use fido2_webauthn_server::{
    routes::api::configure,
    services::{WebAuthnService, UserService},
    schema::{ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialAttestationResponse, ServerAuthenticatorAttestationResponse, ServerPublicKeyCredentialAssertionResponse, ServerAuthenticatorAssertionResponse},
};

#[actix_web::test]
async fn test_attestation_options_basic() {
    // Create services
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service");

    let user_service = UserService::new();

    // Create test app
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service))
            .app_data(actix_web::web::Data::new(user_service))
            .configure(configure)
    ).await;

    // Create request
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
    };

    // Make request
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Check response
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Try to read response body
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    
    // Try to parse as JSON
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["status"], "ok");
    assert!(response_json["challenge"].as_str().is_some());
    assert!(response_json["rp"]["name"].as_str().is_some());
    assert!(response_json["user"]["name"].as_str().is_some());
}

#[actix_web::test]
async fn test_assertion_options_basic() {
    // Create services
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service");

    let user_service = UserService::new();

    // Create test app
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service))
            .app_data(actix_web::web::Data::new(user_service))
            .configure(configure)
    ).await;

    // Create request
    let request = serde_json::json!({
        "username": "test@example.com",
        "userVerification": "preferred"
    });

    // Make request
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Check response
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Try to read response body
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    
    // Try to parse as JSON
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["status"], "ok");
    assert!(response_json["challenge"].as_str().is_some());
    assert_eq!(response_json["rpId"], "localhost");
}

#[actix_web::test]
async fn test_attestation_result_basic() {
    // Create services
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service");

    let user_service = UserService::new();

    // Create test app
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service))
            .app_data(actix_web::web::Data::new(user_service))
            .configure(configure)
    ).await;

    // Create attestation response
    let request = ServerPublicKeyCredentialAttestationResponse {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        raw_id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
            attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
        },
        cred_type: "public-key".to_string(),
        get_client_extension_results: None,
    };

    // Make request
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Check response
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Try to read response body
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    
    // Try to parse as JSON
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    println!("Attestation Response JSON: {}", serde_json::to_string_pretty(&response_json).unwrap());
    assert_eq!(response_json["status"], "ok");
    assert_eq!(response_json["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_basic() {
    // Create services
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service");

    let user_service = UserService::new();

    // Create test app
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(webauthn_service))
            .app_data(actix_web::web::Data::new(user_service))
            .configure(configure)
    ).await;

    // Create assertion response
    let request = ServerPublicKeyCredentialAssertionResponse {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        raw_id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
            signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
        },
        cred_type: "public-key".to_string(),
        get_client_extension_results: None,
    };

    // Make request
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Check response
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Try to read response body
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
    
    // Try to parse as JSON
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["status"], "ok");
    assert_eq!(response_json["errorMessage"], "");
}