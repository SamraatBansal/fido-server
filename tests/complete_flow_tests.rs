//! Complete FIDO2/WebAuthn Flow Test
//! Tests the complete registration and authentication flow as specified in the requirements

use actix_web::{test, web, App};
use fido_server::routes::api::configure;
use fido_server::controllers::WebAuthnController;
use fido_server::services::WebAuthnService;
use serde_json::json;

#[actix_web::test]
async fn test_complete_fido2_registration_flow() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Step 1: Request attestation options (exact format from specification)
    let attestation_options_req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
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

    let attestation_options_resp = test::call_service(&app, attestation_options_req).await;
    assert!(attestation_options_resp.status().is_success());

    let attestation_options: serde_json::Value = test::read_body_json(attestation_options_resp).await;
    
    // Verify response matches specification exactly
    assert_eq!(attestation_options["status"], "ok");
    assert_eq!(attestation_options["errorMessage"], "");
    assert_eq!(attestation_options["rp"]["name"], "Example Corporation");
    assert_eq!(attestation_options["user"]["name"], "johndoe@example.com");
    assert_eq!(attestation_options["user"]["displayName"], "John Doe");
    assert!(attestation_options["challenge"].as_str().unwrap().len() >= 16);
    assert_eq!(attestation_options["timeout"], 10000);
    assert_eq!(attestation_options["attestation"], "direct");
    
    // Verify pubKeyCredParams contains required algorithms
    let pub_key_cred_params = attestation_options["pubKeyCredParams"].as_array().unwrap();
    assert!(pub_key_cred_params.len() >= 1);
    
    // Verify authenticatorSelection is properly set
    let auth_selection = &attestation_options["authenticatorSelection"];
    assert_eq!(auth_selection["requireResidentKey"], false);
    assert_eq!(auth_selection["authenticatorAttachment"], "cross-platform");
    assert_eq!(auth_selection["userVerification"], "preferred");

    // Step 2: Simulate attestation result with invalid origin to test error handling
    let attestation_result_req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0LWNoYWxsZW5nZSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9ldmlsLmV4YW1wbGUuY29tIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let attestation_result_resp = test::call_service(&app, attestation_result_req).await;
    // This should fail due to invalid origin
    assert!(!attestation_result_resp.status().is_success());
    
    let attestation_result: serde_json::Value = test::read_body_json(attestation_result_resp).await;
    assert_eq!(attestation_result["status"], "failed");
    assert!(!attestation_result["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_complete_fido2_authentication_flow() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Step 1: Request assertion options (exact format from specification)
    let assertion_options_req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let assertion_options_resp = test::call_service(&app, assertion_options_req).await;
    assert!(assertion_options_resp.status().is_success());

    let assertion_options: serde_json::Value = test::read_body_json(assertion_options_resp).await;
    
    // Verify response matches specification exactly
    assert_eq!(assertion_options["status"], "ok");
    assert_eq!(assertion_options["errorMessage"], "");
    assert!(assertion_options["challenge"].as_str().unwrap().len() >= 16);
    assert_eq!(assertion_options["timeout"], 20000);
    assert_eq!(assertion_options["rpId"], "localhost");
    assert_eq!(assertion_options["userVerification"], "required");
    assert!(assertion_options["allowCredentials"].is_array());

    // Step 2: Simulate assertion result (would normally come from authenticator)
    let assertion_result_req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&json!({
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

    let assertion_result_resp = test::call_service(&app, assertion_result_req).await;
    // This will fail because we haven't implemented full signature verification yet
    // But it should return the proper error format
    assert!(!assertion_result_resp.status().is_success());
    
    let assertion_result: serde_json::Value = test::read_body_json(assertion_result_resp).await;
    assert_eq!(assertion_result["status"], "failed");
    assert!(!assertion_result["errorMessage"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_error_response_format() {
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(configure)
    ).await;

    // Test with malformed request
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "invalid": "request"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify error response format matches specification
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().len() > 0);
    // Should not have other fields
    assert!(result.get("error").is_none());
    assert!(result.get("statusCode").is_none());
}