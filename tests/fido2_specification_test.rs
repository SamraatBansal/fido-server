//! FIDO2 Specification Compliance Test
//! Tests that verify the server meets the FIDO2 specification requirements

use actix_web::{test, App};
use fido_server::routes::api::configure;
use fido_server::domain::models::*;

#[actix_web::test]
async fn test_fido2_registration_specification_compliance() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // Test 1: Registration Options Request
    let registration_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
        }),
        attestation: Some("direct".to_string()),
    };

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
        test::read_body_json(resp).await;
    
    // Verify FIDO2 specification compliance
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

    // Test 2: Registration Result
    let attestation_result = ServerPublicKeyCredential {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        r#type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
            attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
        }),
        get_client_extension_results: Some(std::collections::HashMap::new()),
    };

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
async fn test_fido2_authentication_specification_compliance() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // First, register a user (simplified flow)
    let registration_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
        }),
        attestation: Some("direct".to_string()),
    };

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Complete registration
    let attestation_result = ServerPublicKeyCredential {
        id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
        r#type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJ0eXN0Ijoid2ViYXV0aG4uY3JlYXRlIn0=".to_string(),
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ".to_string(),
        }),
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_result)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Test 1: Authentication Options Request
    let assertion_request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "johndoe@example.com".to_string(),
        user_verification: Some("required".to_string()),
    };

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
        test::read_body_json(resp).await;
    
    // Verify FIDO2 specification compliance
    assert_eq!(options_response.base.status, "ok");
    assert_eq!(options_response.base.error_message, "");
    assert!(!options_response.challenge.is_empty());
    assert_eq!(options_response.timeout, Some(60000));
    assert_eq!(options_response.rp_id, "localhost");
    assert_eq!(options_response.user_verification, Some("required".to_string()));
    assert!(!options_response.allow_credentials.is_empty());

    // Test 2: Authentication Result
    let assertion_result = ServerPublicKeyCredential {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        r#type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Assertion(ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: "".to_string(),
            client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
        }),
        get_client_extension_results: Some(std::collections::HashMap::new()),
    };

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
async fn test_fido2_error_handling() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // Test error case: Non-existent user for authentication
    let assertion_request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "nonexistent@example.com".to_string(),
        user_verification: Some("required".to_string()),
    };

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404); // Not Found is appropriate for this case
}