//! FIDO2 Conformance Tests
//! 
//! These tests validate that the server meets the FIDO2 conformance requirements
//! and matches the expected request/response format from the conformance tool.

use actix_web::{test, App, web, http};
use serde_json::json;
use fido_server::{
    services::{WebAuthnServiceImpl, WebAuthnConfig},
    controllers::webauthn,
};

#[actix_web::test]
async fn test_attestation_options_success() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = WebAuthnServiceImpl::new(webauthn_config)
        .expect("Failed to create WebAuthn service");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
            .service(
                web::scope("/api")
                    .route("/attestation/options", web::post().to(webauthn::attestation_options))
                    .route("/attestation/result", web::post().to(webauthn::attestation_result))
                    .route("/assertion/options", web::post().to(webauthn::assertion_options))
                    .route("/assertion/result", web::post().to(webauthn::assertion_result))
            )
    ).await;
    
    let request_body = json!({
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
        .uri("/api/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure matches FIDO2 conformance requirements
    assert_eq!(body["status"], "ok");
    // errorMessage should be empty or not present in success response
    match body.get("errorMessage") {
        Some(msg) => assert!(msg.as_str().unwrap().is_empty()),
        None => {} // It's okay if errorMessage is not present
    }
    
    // Verify rp entity
    assert_eq!(body["rp"]["name"], "Example Corporation");
    
    // Verify user entity
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert!(!body["user"]["id"].as_str().unwrap().is_empty());
    
    // Verify challenge is present and non-empty
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    
    // Verify pubKeyCredParams
    assert!(body["pubKeyCredParams"].as_array().unwrap().len() > 0);
    assert_eq!(body["pubKeyCredParams"][0]["type"], "public-key");
    assert_eq!(body["pubKeyCredParams"][0]["alg"], -7);
    
    // Verify timeout
    assert_eq!(body["timeout"], 10000);
    
    // Verify authenticatorSelection
    assert_eq!(body["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(body["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
    assert_eq!(body["authenticatorSelection"]["userVerification"], "preferred");
    
    // Verify attestation
    assert_eq!(body["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = WebAuthnServiceImpl::new(webauthn_config)
        .expect("Failed to create WebAuthn service");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
            .service(
                web::scope("/api")
                    .route("/attestation/options", web::post().to(webauthn::attestation_options))
                    .route("/attestation/result", web::post().to(webauthn::attestation_result))
                    .route("/assertion/options", web::post().to(webauthn::assertion_options))
                    .route("/assertion/result", web::post().to(webauthn::assertion_result))
            )
    ).await;
    
    let request_body = json!({
        "displayName": "John Doe",
        "attestation": "direct"
    });

    let req = test::TestRequest::post()
        .uri("/api/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(!body.get("errorMessage").unwrap().as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = WebAuthnServiceImpl::new(webauthn_config)
        .expect("Failed to create WebAuthn service");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
            .service(
                web::scope("/api")
                    .route("/attestation/options", web::post().to(webauthn::attestation_options))
                    .route("/attestation/result", web::post().to(webauthn::attestation_result))
                    .route("/assertion/options", web::post().to(webauthn::assertion_options))
                    .route("/assertion/result", web::post().to(webauthn::assertion_result))
            )
    ).await;
    
    let request_body = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/api/attestation/result")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    // errorMessage should be empty or not present in success response
    match body.get("errorMessage") {
        Some(msg) => assert!(msg.as_str().unwrap().is_empty()),
        None => {} // It's okay if errorMessage is not present
    }
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = WebAuthnServiceImpl::new(webauthn_config)
        .expect("Failed to create WebAuthn service");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
            .service(
                web::scope("/api")
                    .route("/attestation/options", web::post().to(webauthn::attestation_options))
                    .route("/attestation/result", web::post().to(webauthn::attestation_result))
                    .route("/assertion/options", web::post().to(webauthn::assertion_options))
                    .route("/assertion/result", web::post().to(webauthn::assertion_result))
            )
    ).await;
    
    let request_body = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/api/assertion/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), http::StatusCode::OK);
    
    let body_bytes = test::read_body(resp).await;
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    println!("Response body: {}", body_str);
    let body: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    
    // Verify response structure matches FIDO2 conformance requirements
    assert_eq!(body["status"], "ok");
    // errorMessage should be empty or not present in success response
    match body.get("errorMessage") {
        Some(msg) => assert!(msg.as_str().unwrap().is_empty()),
        None => {} // It's okay if errorMessage is not present
    }
    
    // Verify challenge is present and non-empty
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    
    // Verify timeout
    assert_eq!(body["timeout"], 20000);
    
    // Verify rpId
    assert_eq!(body["rpId"], "localhost");
    
    // Verify allowCredentials (empty for now, so it might not be present)
    match body.get("allowCredentials") {
        Some(creds) => assert!(creds.as_array().unwrap().is_empty()),
        None => {} // It's okay if allowCredentials is not present when empty
    }
    
    // Verify userVerification
    assert_eq!(body["userVerification"], "required");
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = WebAuthnServiceImpl::new(webauthn_config)
        .expect("Failed to create WebAuthn service");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
            .service(
                web::scope("/api")
                    .route("/attestation/options", web::post().to(webauthn::attestation_options))
                    .route("/attestation/result", web::post().to(webauthn::attestation_result))
                    .route("/assertion/options", web::post().to(webauthn::assertion_options))
                    .route("/assertion/result", web::post().to(webauthn::assertion_result))
            )
    ).await;
    
    let request_body = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/api/assertion/result")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), http::StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    // errorMessage should be empty or not present in success response
    match body.get("errorMessage") {
        Some(msg) => assert!(msg.as_str().unwrap().is_empty()),
        None => {} // It's okay if errorMessage is not present
    }
}