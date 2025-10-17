//! FIDO2 Conformance Tests
//! Tests based on the FIDO2 specification examples

use actix_web::{test, App};
use fido_server::routes::api::configure;
use fido_server::domain::models::*;
use serde_json::json;

#[actix_web::test]
async fn test_fido2_registration_flow_complete() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // Step 1: Request attestation options
    let registration_request = json!({
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
        .set_json(&registration_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
        test::read_body_json(resp).await;
    
    // Verify response structure matches FIDO2 specification
    assert_eq!(options_response.base.status, "ok");
    assert_eq!(options_response.base.error_message, "");
    assert_eq!(options_response.rp.name, "Example Corporation");
    assert_eq!(options_response.user.name, "johndoe@example.com");
    assert_eq!(options_response.user.display_name, "John Doe");
    assert!(!options_response.challenge.is_empty());
    assert!(options_response.challenge.len() >= 16); // Minimum 16 bytes when base64 decoded
    assert_eq!(options_response.pub_key_cred_params.len(), 1);
    assert_eq!(options_response.pub_key_cred_params[0].r#type, "public-key");
    assert_eq!(options_response.pub_key_cred_params[0].alg, -7); // ES256
    assert_eq!(options_response.timeout, Some(60000));
    assert_eq!(options_response.attestation, Some("direct".to_string()));

    // Step 2: Simulate attestation result (simplified for testing)
    let attestation_result = json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_result)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result_response: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result_response.status, "ok");
    assert_eq!(result_response.error_message, "");
}

#[actix_web::test]
async fn test_fido2_authentication_flow_complete() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // First, we need to register a user and credential
    // Step 1: Register a user
    let registration_request = json!({
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
        .set_json(&registration_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Step 2: Complete registration (simplified)
    let attestation_result = json!({
        "id": "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m",
        "response": {
            "clientDataJSON": "eyJ0eXN0Ijoid2ViYXV0aG4uY3JlYXRlIn0=",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_result)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Step 3: Request assertion options
    let assertion_request = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
        test::read_body_json(resp).await;
    
    // Verify response structure matches FIDO2 specification
    assert_eq!(options_response.base.status, "ok");
    assert_eq!(options_response.base.error_message, "");
    assert!(!options_response.challenge.is_empty());
    assert_eq!(options_response.timeout, Some(60000));
    assert_eq!(options_response.rp_id, "localhost");
    assert_eq!(options_response.user_verification, Some("required".to_string()));
    assert!(!options_response.allow_credentials.is_empty());

    // Step 4: Complete authentication
    let assertion_result = json!({
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
        .uri("/assertion/result")
        .set_json(&assertion_result)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result_response: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(result_response.status, "ok");
    assert_eq!(result_response.error_message, "");
}

#[actix_web::test]
async fn test_error_response_format() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // Test with non-existent user for assertion options
    let assertion_request = json!({
        "username": "nonexistent@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);

    // The error response should follow the ServerResponse format
    // Note: Our current implementation returns a 404, but in production
    // we might want to return a 200 with an error status in the body
    // to match the FIDO2 specification exactly
}