//! Integration tests for FIDO2 WebAuthn server

use actix_web::{test, App, http::StatusCode};
use serde_json::json;
use fido_server::routes::api::configure;

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
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

    let response = test::call_service(&app, req).await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = test::read_body_json(response).await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert_eq!(result["rp"]["name"], "Example Corporation");
    assert_eq!(result["user"]["name"], "johndoe@example.com");
    assert_eq!(result["user"]["displayName"], "John Doe");
    assert!(result["challenge"].as_str().unwrap().len() >= 16);
    assert!(result["pubKeyCredParams"].as_array().unwrap().len() > 0);
    assert_eq!(result["timeout"], 10000);
    assert_eq!(result["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(result["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
    assert_eq!(result["authenticatorSelection"]["userVerification"], "preferred");
    assert_eq!(result["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
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

    let response = test::call_service(&app, req).await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = test::read_body_json(response).await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let request_body = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/api/assertion/options")
        .set_json(&request_body)
        .to_request();

    let response = test::call_service(&app, req).await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = test::read_body_json(response).await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
    assert!(result["challenge"].as_str().unwrap().len() >= 16);
    assert_eq!(result["timeout"], 20000);
    assert_eq!(result["rpId"], "example.com");
    assert_eq!(result["userVerification"], "required");
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = TestServer::start(|| {
        App::new().configure(configure)
    });

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

    let response = app
        .post("/api/assertion/result")
        .send_json(&request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = response.json().await;
    
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
}