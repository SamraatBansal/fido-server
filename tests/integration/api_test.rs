//! Integration tests for FIDO2/WebAuthn API

use actix_web::{test, App, http::StatusCode};
use serde_json::json;
use uuid::Uuid;
use std::sync::Arc;
use async_trait::async_trait;

use fido_server::{
    services::{MockWebAuthnService, WebAuthnService},
    routes::configure_routes,
    schema::*,
};

/// Create test app state
async fn create_test_app() -> Arc<dyn WebAuthnService> {
    // For testing, we'll use in-memory repositories or mock implementations
    // For now, let's create a simple mock service
    Arc::new(MockWebAuthnService::new())
}

/// Mock WebAuthn service for testing
struct MockWebAuthnService;

impl MockWebAuthnService {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl fido_server::services::WebAuthnService for MockWebAuthnService {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> fido_server::error::Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let mut response = ServerPublicKeyCredentialCreationOptionsResponse::default();
        response.user = ServerPublicKeyCredentialUserEntity {
            id: "S3932ee31vKEC0JtJMIQ".to_string(),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        };
        response.challenge = "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string();
        response.exclude_credentials = Some(vec![ServerPublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "opQf1WmYAa5aupUKJIQp".to_string(),
            transports: None,
        }]);
        response.authenticator_selection = request.authenticator_selection;
        response.attestation = request.attestation;
        
        Ok(response)
    }

    async fn verify_registration(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> fido_server::error::Result<ServerResponse> {
        Ok(ServerResponse::success())
    }

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> fido_server::error::Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let mut response = ServerPublicKeyCredentialGetOptionsResponse::default();
        response.challenge = "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string();
        response.allow_credentials = vec![ServerPublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
            transports: None,
        }];
        response.user_verification = request.user_verification;
        
        Ok(response)
    }

    async fn verify_authentication(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> fido_server::error::Result<ServerResponse> {
        Ok(ServerResponse::success())
    }
}

#[actix_web::test]
async fn test_attestation_options_success() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/attestation/options")
        .set_json(json!({
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
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(response.status, "ok");
    assert_eq!(response.rp.name, "Example Corporation");
    assert_eq!(response.user.name, "johndoe@example.com");
    assert_eq!(response.user.display_name, "John Doe");
    assert!(!response.challenge.is_empty());
    assert_eq!(response.pub_key_cred_params.len(), 1);
    assert_eq!(response.pub_key_cred_params[0].alg, -7);
    assert_eq!(response.authenticator_selection.as_ref().unwrap().require_resident_key, Some(false));
    assert_eq!(response.attestation, Some("direct".to_string()));
}

#[actix_web::test]
async fn test_attestation_result_success() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/attestation/result")
        .set_json(json!({
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
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(response.status, "ok");
    assert!(response.error_message.is_empty());
}

#[actix_web::test]
async fn test_assertion_options_success() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/assertion/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response: ServerPublicKeyCredentialGetOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(response.status, "ok");
    assert!(!response.challenge.is_empty());
    assert_eq!(response.rp_id, "localhost");
    assert_eq!(response.allow_credentials.len(), 1);
    assert_eq!(response.allow_credentials[0].credential_type, "public-key");
    assert_eq!(response.user_verification, Some("required".to_string()));
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/assertion/result")
        .set_json(json!({
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
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let response: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(response.status, "ok");
    assert!(response.error_message.is_empty());
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/attestation/options")
        .set_json(json!({
            "displayName": "John Doe"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/assertion/options")
        .set_json(json!({
            "username": "nonexistent@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    // This should return an error since the user doesn't exist
    assert!(resp.status().is_client_error() || resp.status().is_server_error());
}