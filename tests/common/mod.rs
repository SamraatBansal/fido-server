//! Common test utilities and helpers

use actix_web::{test, App, dev::ServiceResponse};
use fido2_webauthn_server::{
    routes, services, 
    schema::*,
    error::AppError,
};
use base64::Engine;

/// Test application configuration
pub struct TestApp {
    pub app: actix_web::test::TestApp,
    pub webauthn_service: services::WebAuthnService,
    pub user_service: services::UserService,
}

impl TestApp {
    /// Create a new test application instance
    pub async fn new() -> Self {
        let webauthn_service = services::WebAuthnService::new(
            "localhost",
            "FIDO Test Server",
            "http://localhost:8080",
        ).expect("Failed to create WebAuthn service");

        let user_service = services::UserService::new();

        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(webauthn_service.clone()))
                .app_data(actix_web::web::Data::new(user_service.clone()))
                .configure(routes::api::configure)
        ).await;

        Self {
            app,
            webauthn_service,
            user_service,
        }
    }

    /// Make a POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> actix_web::dev::ServiceResponse {
        let req = test::TestRequest::post()
            .uri(path)
            .set_json(body)
            .to_request();

        test::call_service(&self.app, req).await
    }

    /// Make a POST request and get JSON response
    pub async fn post_json_response<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, AppError> {
        let req = test::TestRequest::post()
            .uri(path)
            .set_json(body)
            .to_request();

        let resp = test::call_service(&self.app, req).await;
        
        if resp.status().is_success() {
            let body = test::read_body(resp).await;
            serde_json::from_slice(&body).map_err(AppError::SerializationError)
        } else {
            Err(AppError::BadRequest(format!("Request failed: {}", resp.status())))
        }
    }
}

/// Test data factory for creating valid test data
pub struct TestDataFactory;

impl TestDataFactory {
    /// Create a valid registration options request
    pub fn create_registration_request(
        username: &str,
        display_name: &str,
    ) -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: username.to_string(),
            display_name: display_name.to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
                authenticator_attachment: Some("cross-platform".to_string()),
            }),
            attestation: Some("direct".to_string()),
        }
    }

    /// Create a valid authentication options request
    pub fn create_authentication_request(
        username: Option<&str>,
        user_verification: Option<&str>,
    ) -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: username.map(|s| s.to_string()),
            user_verification: user_verification.map(|s| s.to_string()),
        }
    }

    /// Create a valid attestation response
    pub fn create_attestation_response() -> ServerPublicKeyCredentialAttestationResponse {
        ServerPublicKeyCredentialAttestationResponse {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            response: ServerAuthenticatorAttestationResponse {
                client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
                attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
            },
            cred_type: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }

    /// Create a valid assertion response
    pub fn create_assertion_response() -> ServerPublicKeyCredentialAssertionResponse {
        ServerPublicKeyCredentialAssertionResponse {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
                signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: Some("".to_string()),
            },
            cred_type: "public-key".to_string(),
            get_client_extension_results: None,
        }
    }

    /// Create invalid base64url string
    pub fn create_invalid_base64url() -> String {
        "invalid!base64@string".to_string()
    }

    /// Create oversized string for testing limits
    pub fn create_oversized_string(size: usize) -> String {
        "a".repeat(size)
    }
}

/// Assertion helpers for test validation
pub struct TestAssertions;

impl TestAssertions {
    /// Assert that a response has the expected success status
    pub fn assert_success_response(response: &ServerResponse) {
        assert_eq!(response.status, "ok");
        assert!(response.error_message.is_empty());
    }

    /// Assert that a response has the expected error status
    pub fn assert_error_response(response: &ServerResponse, expected_error: &str) {
        assert_eq!(response.status, "failed");
        assert!(response.error_message.contains(expected_error));
    }

    /// Assert that a challenge is valid base64url and has reasonable length
    pub fn assert_valid_challenge(challenge: &str) {
        assert!(!challenge.is_empty(), "Challenge should not be empty");
        assert!(challenge.len() >= 16, "Challenge should be at least 16 characters");
        assert!(challenge.len() <= 128, "Challenge should not exceed 128 characters");
        
        // Test that it's valid base64url
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge).is_ok(), 
                "Challenge should be valid base64url");
    }

    /// Assert that credential ID is valid
    pub fn assert_valid_credential_id(cred_id: &str) {
        assert!(!cred_id.is_empty(), "Credential ID should not be empty");
        assert!(cred_id.len() <= 1024, "Credential ID should not exceed 1024 characters");
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cred_id).is_ok(),
                "Credential ID should be valid base64url");
    }
}

/// Create a test app for integration tests
pub async fn create_test_app() -> TestApp {
    TestApp::new().await
}

/// Make a POST request with JSON body
pub async fn post_json<T: serde::Serialize>(
    app: &impl actix_web::dev::Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    path: &str,
    body: &T,
) -> ServiceResponse {
    let req = test::TestRequest::post()
        .uri(path)
        .set_json(body)
        .to_request();

    test::call_service(app, req).await
}

/// Read JSON response body
pub async fn read_body_json<T: serde::de::DeserializeOwned>(
    resp: ServiceResponse,
) -> Result<T, AppError> {
    if resp.status().is_success() {
        let body = test::read_body(resp).await;
        serde_json::from_slice(&body).map_err(|e| AppError::SerializationError(e))
    } else {
        Err(AppError::ValidationError(format!("Request failed: {}", resp.status())))
    }
}

/// Create a test WebAuthn service
pub async fn create_test_webauthn_service() -> services::WebAuthnService {
    services::WebAuthnService::new(
        "localhost",
        "FIDO Test Server",
        "http://localhost:8080",
    ).expect("Failed to create WebAuthn service")
}

/// Mock service implementations for testing
pub mod mocks {
    use super::*;
    use mockall::mock;

    mock! {
        pub WebAuthnService {}

        impl Clone for WebAuthnService {
            fn clone(&self) -> Self;
        }
    }

    mock! {
        pub UserService {}

        impl Clone for UserService {
            fn clone(&self) -> Self;
        }
    }
}