//! FIDO2/WebAuthn Conformance Tests
//! 
//! Tests that verify the server implements the FIDO2 specification correctly
//! and can handle requests/responses in the expected format.

use actix_web::{test, web, App};
use serde_json::json;

use fido_server::dto::*;

/// Test helper to create a test app with all routes
async fn create_test_app() -> actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    impl actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
    actix_web::Error,
> {
    test::init_service(
        App::new().configure(|cfg| {
            cfg.route("/health", web::get().to(health_check))
                .route("/attestation/options", web::post().to(registration_options))
                .route("/attestation/result", web::post().to(registration_result))
                .route("/assertion/options", web::post().to(authentication_options))
                .route("/assertion/result", web::post().to(authentication_result));
        })
    ).await
}

/// Health check endpoint
async fn health_check() -> actix_web::Result<actix_web::HttpResponse> {
    Ok(actix_web::HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Registration options endpoint
async fn registration_options(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        server_response: ServerResponse::ok(),
        rp: fido_server::dto::registration::PublicKeyCredentialRpEntity {
            id: Some("localhost".to_string()),
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: "U3932ee31vKEC0JtJMIQ".to_string(),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        },
        challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        pub_key_cred_params: vec![
            fido_server::dto::registration::PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7,
            }
        ],
        timeout: Some(10000),
        exclude_credentials: vec![],
        authenticator_selection: request.authenticator_selection.clone(),
        attestation: request.attestation.clone(),
        extensions: None,
    };

    Ok(actix_web::HttpResponse::Ok().json(response))
}

/// Registration result endpoint
async fn registration_result(
    _request: web::Json<RegistrationResultRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    Ok(actix_web::HttpResponse::Ok().json(ServerResponse::ok()))
}

/// Authentication options endpoint
async fn authentication_options(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        server_response: ServerResponse::ok(),
        challenge: "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
        timeout: Some(20000),
        rp_id: Some("localhost".to_string()),
        allow_credentials: vec![],
        user_verification: request.user_verification.clone(),
        extensions: None,
    };

    Ok(actix_web::HttpResponse::Ok().json(response))
}

/// Authentication result endpoint
async fn authentication_result(
    _request: web::Json<AuthenticationResultRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    Ok(actix_web::HttpResponse::Ok().json(ServerResponse::ok()))
}

#[actix_web::test]
async fn test_health_endpoint() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "FIDO Server");
    assert!(body["timestamp"].is_string());
}

#[actix_web::test]
async fn test_registration_options_conformance() {
    let app = create_test_app().await;

    // Test request that matches FIDO conformance test format
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
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    
    // Verify the response matches FIDO conformance test expectations
    assert_eq!(body.server_response.status, "ok");
    assert_eq!(body.server_response.error_message, "");
    assert_eq!(body.rp.name, "Example Corporation");
    assert_eq!(body.user.name, "johndoe@example.com");
    assert_eq!(body.user.display_name, "John Doe");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.pub_key_cred_params.len(), 1);
    assert_eq!(body.pub_key_cred_params[0].type_, "public-key");
    assert_eq!(body.pub_key_cred_params[0].alg, -7);
    assert_eq!(body.timeout, Some(10000));
}

#[actix_web::test]
async fn test_registration_result_conformance() {
    let app = create_test_app().await;

    // Test request that matches FIDO conformance test format
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
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}

#[actix_web::test]
async fn test_authentication_options_conformance() {
    let app = create_test_app().await;

    // Test request that matches FIDO conformance test format
    let request_body = json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(resp).await;
    
    // Verify the response matches FIDO conformance test expectations
    assert_eq!(body.server_response.status, "ok");
    assert_eq!(body.server_response.error_message, "");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.timeout, Some(20000));
    assert_eq!(body.rp_id, Some("localhost".to_string()));
}

#[actix_web::test]
async fn test_authentication_result_conformance() {
    let app = create_test_app().await;

    // Test request that matches FIDO conformance test format
    let request_body = json!({
        "id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response":{
            "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle":"",
            "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "getClientExtensionResults": {},
        "type":"public-key"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}

#[actix_web::test]
async fn test_error_response_format() {
    let app = create_test_app().await;

    // Test with invalid JSON to trigger error response
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_header("content-type", "application/json")
        .set_payload("{invalid json}")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].is_string());
}