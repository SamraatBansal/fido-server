//! FIDO2 Conformance Tests
//! 
//! These tests verify that the server implements the FIDO2/WebAuthn API
//! according to the conformance requirements.

use actix_web::{test, web, App};
use fido_server::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialGetOptionsRequest,
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference,
    ServerPublicKeyCredential,
};
use serde_json::json;

#[actix_web::test]
async fn test_attestation_options_success() {
    let app = test::init_service(
        App::new().configure(fido_server::routes::configure_routes)
    ).await;

    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: false,
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: "preferred".to_string(),
        }),
        attestation: Some(AttestationConveyancePreference::Direct),
    };

    let response = server
        .post("/api/v1/attestation/options")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json_response: serde_json::Value = response.json().await.unwrap();
    
    // Verify response structure according to FIDO2 conformance
    assert_eq!(json_response["status"], "ok");
    assert_eq!(json_response["errorMessage"], "");
    
    // Verify rp entity
    assert_eq!(json_response["rp"]["name"], "Example Corporation");
    
    // Verify user entity
    assert_eq!(json_response["user"]["name"], "johndoe@example.com");
    assert_eq!(json_response["user"]["displayName"], "John Doe");
    assert!(json_response["user"]["id"].is_string());
    
    // Verify challenge is present and base64url encoded
    let challenge = json_response["challenge"].as_str().unwrap();
    assert!(!challenge.is_empty());
    assert!(challenge.len() >= 16); // Minimum 16 bytes when base64url encoded
    
    // Verify pubKeyCredParams
    assert!(json_response["pubKeyCredParams"].as_array().unwrap().len() > 0);
    let cred_param = &json_response["pubKeyCredParams"][0];
    assert_eq!(cred_param["type"], "public-key");
    assert_eq!(cred_param["alg"], -7); // ES256
    
    // Verify timeout
    assert!(json_response["timeout"].is_number());
    
    // Verify authenticatorSelection
    assert_eq!(json_response["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(json_response["authenticatorSelection"]["userVerification"], "preferred");
    
    // Verify attestation
    assert_eq!(json_response["attestation"], "direct");
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let app = fido_server::routes::configure_routes;
    let mut server = TestServer::new(|| {
        actix_web::App::new().configure(fido_server::routes::configure_routes)
    });

    let request = json!({
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let response = server
        .post("/api/v1/attestation/options")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

#[actix_web::test]
async fn test_attestation_options_missing_display_name() {
    let app = fido_server::routes::configure_routes;
    let mut server = TestServer::new(|| {
        actix_web::App::new().configure(fido_server::routes::configure_routes)
    });

    let request = json!({
        "username": "johndoe@example.com",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let response = server
        .post("/api/v1/attestation/options")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let app = fido_server::routes::configure_routes;
    let mut server = TestServer::new(|| {
        actix_web::App::new().configure(fido_server::routes::configure_routes)
    });

    // Mock attestation result (simplified for testing)
    let request = ServerPublicKeyCredential {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        cred_type: "public-key".to_string(),
        response: serde_json::json!({
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        }),
        get_client_extension_results: Some(json!({})),
    };

    let response = server
        .post("/api/v1/attestation/result")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json_response: serde_json::Value = response.json().await.unwrap();
    assert_eq!(json_response["status"], "ok");
    assert_eq!(json_response["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = fido_server::routes::configure_routes;
    let mut server = TestServer::new(|| {
        actix_web::App::new().configure(fido_server::routes::configure_routes)
    });

    let request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "nonexistent@example.com".to_string(),
        user_verification: Some("required".to_string()),
    };

    let response = server
        .post("/api/v1/assertion/options")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 404);

    let json_response: serde_json::Value = response.json().await.unwrap();
    assert_eq!(json_response["status"], "failed");
    assert!(json_response["errorMessage"].as_str().unwrap().contains("User does not exists"));
}

#[actix_web::test]
async fn test_assertion_options_missing_username() {
    let app = fido_server::routes::configure_routes;
    let mut server = TestServer::new(|| {
        actix_web::App::new().configure(fido_server::routes::configure_routes)
    });

    let request = json!({
        "userVerification": "required"
    });

    let response = server
        .post("/api/v1/assertion/options")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = fido_server::routes::configure_routes;
    let mut server = TestServer::new(|| {
        actix_web::App::new().configure(fido_server::routes::configure_routes)
    });

    // Mock assertion result (simplified for testing)
    let request = ServerPublicKeyCredential {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        cred_type: "public-key".to_string(),
        response: serde_json::json!({
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        }),
        get_client_extension_results: Some(json!({})),
    };

    let response = server
        .post("/api/v1/assertion/result")
        .send_json(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let json_response: serde_json::Value = response.json().await.unwrap();
    assert_eq!(json_response["status"], "ok");
    assert_eq!(json_response["errorMessage"], "");
}