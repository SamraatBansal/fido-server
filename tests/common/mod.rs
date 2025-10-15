use actix_test::TestServer;
use actix_web::{web, App, middleware::Logger};
use fido2_webauthn_server::{config::AppConfig, handlers};
use serde_json::Value;

pub struct TestApp {
    pub server: TestServer,
    pub config: AppConfig,
}

impl TestApp {
    pub async fn new() -> Self {
        let config = AppConfig::for_testing();
        
        let server = actix_test::start(move || {
            App::new()
                .app_data(web::Data::new(config.clone()))
                .wrap(Logger::default())
                .wrap(actix_cors::Cors::permissive())
                .service(handlers::attestation_options_legacy)
                .service(handlers::attestation_result_legacy)
                .service(handlers::assertion_options_legacy)
                .service(handlers::assertion_result_legacy)
        });

        Self { server, config }
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> reqwest::Response {
        let client = reqwest::Client::new();
        client
            .post(&format!("{}{}", self.server.url(""), path))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .expect("Failed to send request")
    }
}

// Test data factories
pub mod fixtures {
    use serde_json::{json, Value};

    pub fn valid_registration_request() -> Value {
        json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })
    }

    pub fn minimal_registration_request() -> Value {
        json!({
            "username": "alice@example.com",
            "displayName": "Alice Smith"
        })
    }

    pub fn invalid_registration_request_missing_username() -> Value {
        json!({
            "displayName": "John Doe",
            "attestation": "direct"
        })
    }

    pub fn invalid_registration_request_empty_username() -> Value {
        json!({
            "username": "",
            "displayName": "John Doe"
        })
    }

    pub fn valid_attestation_result() -> Value {
        json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        })
    }

    pub fn valid_authentication_request() -> Value {
        json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        })
    }

    pub fn valid_assertion_result() -> Value {
        json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        })
    }

    pub fn invalid_attestation_malformed_json() -> Value {
        json!({
            "id": "invalid-id",
            "response": {
                "clientDataJSON": "invalid-base64",
                "attestationObject": "invalid-base64"
            }
        })
    }

    pub fn security_test_vectors() -> Vec<(&'static str, Value)> {
        vec![
            ("empty_request", json!({})),
            ("null_values", json!({
                "username": null,
                "displayName": null
            })),
            ("oversized_username", json!({
                "username": "a".repeat(1000),
                "displayName": "Test User"
            })),
            ("sql_injection_attempt", json!({
                "username": "'; DROP TABLE users; --",
                "displayName": "Test User"
            })),
            ("xss_attempt", json!({
                "username": "<script>alert('xss')</script>",
                "displayName": "Test User"
            })),
            ("unicode_overflow", json!({
                "username": "\u{10000}".repeat(100),
                "displayName": "Test User"
            })),
        ]
    }
}