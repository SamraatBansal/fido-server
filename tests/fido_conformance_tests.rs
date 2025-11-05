//! FIDO Conformance Tests
//! 
//! These tests validate that the server meets FIDO Alliance conformance requirements

use actix_web::{test, web, App};
use fido_server::webauthn::*;
use fido_server::webauthn::memory_store::*;
use fido_server::webauthn::service::*;
use fido_server::controllers::{WebAuthnController, begin_registration, finish_registration, begin_authentication, finish_authentication};
use fido_server::routes::api::configure;
use std::sync::Arc;

async fn create_conformance_test_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let config = WebAuthnConfig {
        rp_name: "Example Corporation".to_string(),
        rp_id: "localhost".to_string(),
        rp_origin: "http://localhost:3000".to_string(),
        timeout: 10000,
        require_user_verification: false,
        supported_algorithms: vec![-7, -257], // ES256, RS256
    };
    
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
async fn test_fido_registration_request_response_format() {
    let app = create_conformance_test_app().await;
    
    // Test the exact request/response format from FIDO specification
    let request = test::TestRequest::post()
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
    
    let response = test::call_service(&app, request).await;
    assert!(response.status().is_success());
    
    let response_body: serde_json::Value = test::read_body_json(response).await;
    
    // Verify exact FIDO specification response format
    assert_eq!(response_body["status"], "ok");
    assert_eq!(response_body["errorMessage"], "");
    
    // Verify RP entity
    assert_eq!(response_body["rp"]["name"], "Example Corporation");
    
    // Verify user entity
    assert_eq!(response_body["user"]["name"], "johndoe@example.com");
    assert_eq!(response_body["user"]["displayName"], "John Doe");
    assert!(!response_body["user"]["id"].as_str().unwrap().is_empty());
    
    // Verify challenge
    let challenge = response_body["challenge"].as_str().unwrap();
    assert!(!challenge.is_empty());
    assert!(!challenge.contains('='));
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
    
    // Verify pubKeyCredParams
    let pub_key_cred_params = response_body["pubKeyCredParams"].as_array().unwrap();
    assert!(pub_key_cred_params.len() >= 1);
    
    // Check for ES256 (-7)
    let has_es256 = pub_key_cred_params.iter().any(|param| {
        param["type"] == "public-key" && param["alg"] == -7
    });
    assert!(has_es256);
    
    // Verify timeout
    assert_eq!(response_body["timeout"], 10000);
    
    // Verify authenticatorSelection
    assert_eq!(response_body["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(response_body["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
    assert_eq!(response_body["authenticatorSelection"]["userVerification"], "preferred");
    
    // Verify attestation
    assert_eq!(response_body["attestation"], "direct");
}

#[actix_web::test]
async fn test_fido_registration_attestation_response() {
    let app = create_conformance_test_app().await;
    
    // First get a challenge
    let begin_request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "attestation": "none"
        }))
        .to_request();
    
    let begin_response = test::call_service(&app, begin_request).await;
    assert!(begin_response.status().is_success());
    
    let begin_response_body: serde_json::Value = test::read_body_json(begin_response).await;
    let challenge = begin_response_body["challenge"].as_str().unwrap();
    
    // Test attestation result with mock data
    let attestation_request = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&serde_json::json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": create_mock_client_data_json_for_challenge(challenge, "webauthn.create"),
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();
    
    let response = test::call_service(&app, attestation_request).await;
    
    // Should return proper ServerResponse format
    let response_body: serde_json::Value = test::read_body_json(response).await;
    assert!(response_body["status"].is_string());
    assert!(response_body["errorMessage"].is_string());
}

#[actix_web::test]
async fn test_fido_authentication_request_response_format() {
    let app = create_conformance_test_app().await;
    
    // Test the exact request/response format from FIDO specification
    let request = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&serde_json::json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();
    
    let response = test::call_service(&app, request).await;
    
    // Should fail since user doesn't exist, but return proper error format
    let response_body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(response_body["status"], "failed");
    assert!(!response_body["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_fido_authentication_assertion_response() {
    let app = create_conformance_test_app().await;
    
    // Test assertion result with mock data
    let assertion_request = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&serde_json::json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": create_mock_client_data_json_for_challenge("mock_challenge", "webauthn.get")
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();
    
    let response = test::call_service(&app, assertion_request).await;
    
    // Should return proper ServerResponse format
    let response_body: serde_json::Value = test::read_body_json(response).await;
    assert!(response_body["status"].is_string());
    assert!(response_body["errorMessage"].is_string());
}

#[actix_web::test]
async fn test_fido_error_response_format() {
    let app = create_conformance_test_app().await;
    
    // Test various error conditions to ensure proper error format
    
    // 1. Missing username
    let request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "displayName": "John Doe"
        }))
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), 400);
    
    let response_body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(response_body["status"], "failed");
    assert!(!response_body["errorMessage"].as_str().unwrap().is_empty());
    
    // 2. Invalid JSON
    let request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_payload("{ invalid json }")
        .insert_header(("content-type", "application/json"))
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), 400);
}

#[actix_web::test]
async fn test_fido_challenge_requirements() {
    let app = create_conformance_test_app().await;
    
    let request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert!(response.status().is_success());
    
    let response_body: serde_json::Value = test::read_body_json(response).await;
    let challenge = response_body["challenge"].as_str().unwrap();
    
    // FIDO requirements: minimum 16 bytes, maximum 64 bytes when base64url decoded
    use base64::{Engine as _, engine::general_purpose};
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(challenge).unwrap();
    assert!(decoded.len() >= 16);
    assert!(decoded.len() <= 64);
    
    // Must be base64url encoded without padding
    assert!(!challenge.contains('='));
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
    
    // Challenge should be unique
    let request2 = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "username": "test2@example.com",
            "displayName": "Test User 2"
        }))
        .to_request();
    
    let response2 = test::call_service(&app, request2).await;
    let response_body2: serde_json::Value = test::read_body_json(response2).await;
    let challenge2 = response_body2["challenge"].as_str().unwrap();
    
    assert_ne!(challenge, challenge2);
}

#[actix_web::test]
async fn test_fido_algorithm_support() {
    let app = create_conformance_test_app().await;
    
    let request = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .to_request();
    
    let response = test::call_service(&app, request).await;
    assert!(response.status().is_success());
    
    let response_body: serde_json::Value = test::read_body_json(response).await;
    let pub_key_cred_params = response_body["pubKeyCredParams"].as_array().unwrap();
    
    // FIDO requires support for ES256 (-7) and RS256 (-257)
    let algorithms: Vec<i32> = pub_key_cred_params.iter()
        .filter_map(|param| param["alg"].as_i64())
        .map(|alg| alg as i32)
        .collect();
    
    assert!(algorithms.contains(&-7)); // ES256
    assert!(algorithms.contains(&-257)); // RS256
    
    // All parameters should have type "public-key"
    for param in pub_key_cred_params {
        assert_eq!(param["type"], "public-key");
    }
}

fn create_mock_client_data_json_for_challenge(challenge: &str, typ: &str) -> String {
    use base64::{Engine as _, engine::general_purpose};
    
    let client_data = serde_json::json!({
        "type": typ,
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "hashAlgorithm": "SHA-256"
    });
    
    let client_data_str = client_data.to_string();
    general_purpose::URL_SAFE_NO_PAD.encode(client_data_str.as_bytes())
}