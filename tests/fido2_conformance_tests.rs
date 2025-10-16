//! FIDO2 Conformance Tests - Exact examples from specification

use actix_web::{test, App, web::Data};
use fido_server::routes::api::configure;
use fido_server::models::ServerPublicKeyCredentialCreationOptionsRequest;
use fido_server::services::{WebAuthnService, WebAuthnConfig};
use std::sync::Arc;

#[actix_web::test]
async fn test_fido2_conformance_registration_options() {
    let app = test::init_service(App::new().configure(configure)).await;

    // Exact request from FIDO2 specification
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;

    // Verify exact response structure from specification
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert_eq!(body["rp"]["name"], "Example Corporation");
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    assert!(body["challenge"].as_str().unwrap().len() >= 16);
    assert!(body["challenge"].as_str().unwrap().len() <= 64);
    
    // Verify pubKeyCredParams
    assert_eq!(body["pubKeyCredParams"].as_array().unwrap().len(), 1);
    assert_eq!(body["pubKeyCredParams"][0]["type"], "public-key");
    assert_eq!(body["pubKeyCredParams"][0]["alg"], -7);
    
    assert_eq!(body["timeout"], 10000);
    assert_eq!(body["attestation"], "direct");
    
    // Verify authenticatorSelection is echoed back
    assert_eq!(body["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(body["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
    assert_eq!(body["authenticatorSelection"]["userVerification"], "preferred");
}

#[actix_web::test]
async fn test_fido2_conformance_registration_result() {
    let app = test::init_service(App::new().configure(configure)).await;

    // Exact request from FIDO2 specification
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&serde_json::json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
}

#[actix_web::test]
async fn test_fido2_conformance_authentication_options() {
    let app = test::init_service(App::new().configure(configure)).await;

    // Exact request from FIDO2 specification
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&serde_json::json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;

    // Verify exact response structure from specification
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    assert!(body["challenge"].as_str().unwrap().len() >= 16);
    assert!(body["challenge"].as_str().unwrap().len() <= 64);
    assert_eq!(body["timeout"], 20000);
    assert_eq!(body["rpId"], "example.com");
    assert_eq!(body["userVerification"], "required");
    
    // Verify allowCredentials structure
    assert!(body["allowCredentials"].is_array());
}

#[actix_web::test]
async fn test_fido2_conformance_authentication_result() {
    let app = test::init_service(App::new().configure(configure)).await;

    // Exact request from FIDO2 specification
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&serde_json::json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
}

#[actix_web::test]
async fn test_fido2_conformance_error_response_format() {
    let app = test::init_service(App::new().configure(configure)).await;

    // Test error response format matches specification
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&serde_json::json!({
            "id": "",
            "response": {
                "clientDataJSON": "eyJ0ZXN0IjoidmFsdWUifQ==",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA"
            },
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(!body["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_fido2_security_challenge_requirements() {
    let app = test::init_service(App::new().configure(configure)).await;

    // Test that challenges are cryptographically random and proper length
    let mut challenges = Vec::new();
    
    for _ in 0..10 {
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&ServerPublicKeyCredentialCreationOptionsRequest {
                username: format!("test{}@example.com", rand::random::<u32>()),
                display_name: "Test User".to_string(),
                authenticator_selection: None,
                attestation: None,
            })
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = test::read_body_json(resp).await;
        let challenge = body["challenge"].as_str().unwrap().to_string();
        
        // Verify challenge length (16-64 bytes when base64url encoded)
        assert!(challenge.len() >= 16);
        assert!(challenge.len() <= 64);
        
        // Verify challenge uniqueness
        assert!(!challenges.contains(&challenge));
        challenges.push(challenge);
    }
}