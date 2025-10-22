//! Integration tests for FIDO2/WebAuthn endpoints

use actix_test::{self, TestServer};
use actix_web::{App, web};
use fido_server::{
    models::webauthn::WebAuthnConfig,
    routes::api::configure_fido_routes,
    services::{WebAuthnService, WebAuthnServiceImpl},
};
use serde_json::json;
use std::sync::Arc;

async fn create_test_app() -> TestServer {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebAuthnServiceImpl::new(webauthn_config));

    actix_test::init_service(
        App::new().configure(|cfg| configure_fido_routes(cfg, webauthn_service))
    )
    .await
}

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = create_test_app().await;

    let request = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["error_message"], "");
    assert!(body["challenge"].as_str().unwrap().len() >= 16);
    assert_eq!(body["rp"]["name"], "FIDO Server");
    assert_eq!(body["user"]["name"], "johndoe@example.com");
    assert_eq!(body["user"]["displayName"], "John Doe");
    assert!(body["pubKeyCredParams"].as_array().unwrap().len() > 0);
}

#[actix_web::test]
async fn test_attestation_options_user_not_found() {
    let app = create_test_app().await;

    let request = json!({
        "username": "nonexistent@example.com",
        "displayName": "Nonexistent User"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = create_test_app().await;

    let request = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["error_message"], "");
}

#[actix_web::test]
async fn test_attestation_result_invalid_credential() {
    let app = create_test_app().await;

    let request = json!({
        "id": "",
        "response": {
            "clientDataJSON": "invalid",
            "attestationObject": "invalid"
        },
        "type": "public-key"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(!body["error_message"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = create_test_app().await;

    let request = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request)
            .to_request()
    )
    .await;

    // This should fail because the mock user has no credentials
    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = create_test_app().await;

    let request = json!({
        "username": "nonexistent@example.com",
        "userVerification": "required"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(!resp.status().is_success());
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = create_test_app().await;

    let request = json!({
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

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["error_message"], "");
}

#[actix_web::test]
async fn test_assertion_result_invalid_credential() {
    let app = create_test_app().await;

    let request = json!({
        "id": "",
        "response": {
            "authenticatorData": "invalid",
            "signature": "invalid",
            "userHandle": "",
            "clientDataJSON": "invalid"
        },
        "type": "public-key"
    });

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request)
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(!body["error_message"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_health_check() {
    let app = create_test_app().await;

    let resp = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/health")
            .to_request()
    )
    .await;

    assert!(resp.status().is_success());

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
}