use crate::api::models::*;
use crate::config::AppConfig;
use actix_web::{test, web, App};
use serde_json::json;
use std::collections::HashMap;

/// Test data factory for creating valid attestation options requests
pub fn create_valid_attestation_options_request() -> AttestationOptionsRequest {
    AttestationOptionsRequest {
        username: "johndoe@example.com".to_string(),
        display_name: "John Doe".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
            resident_key: None,
        }),
        attestation: "direct".to_string(),
    }
}

/// Test data factory for creating valid assertion options requests
pub fn create_valid_assertion_options_request() -> AssertionOptionsRequest {
    AssertionOptionsRequest {
        username: "johndoe@example.com".to_string(),
        user_verification: Some("required".to_string()),
    }
}

/// Test data factory for creating valid attestation result requests
pub fn create_valid_attestation_result_request() -> AttestationResultRequest {
    AttestationResultRequest {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        raw_id: None,
        response: AttestationResponse {
            client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
            attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
        },
        get_client_extension_results: Some(HashMap::new()),
        cred_type: "public-key".to_string(),
    }
}

/// Test data factory for creating valid assertion result requests
pub fn create_valid_assertion_result_request() -> AssertionResultRequest {
    AssertionResultRequest {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        raw_id: None,
        response: AssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
        },
        get_client_extension_results: Some(HashMap::new()),
        cred_type: "public-key".to_string(),
    }
}

/// Create invalid requests for negative testing
pub fn create_invalid_attestation_options_requests() -> Vec<serde_json::Value> {
    vec![
        // Missing username
        json!({
            "displayName": "John Doe",
            "attestation": "direct"
        }),
        // Missing displayName
        json!({
            "username": "johndoe@example.com",
            "attestation": "direct"
        }),
        // Invalid username format
        json!({
            "username": "",
            "displayName": "John Doe",
            "attestation": "direct"
        }),
        // Invalid attestation value
        json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "attestation": "invalid"
        }),
        // Malformed JSON structure
        json!({
            "username": 123,
            "displayName": "John Doe",
            "attestation": "direct"
        }),
    ]
}

pub fn create_invalid_assertion_options_requests() -> Vec<serde_json::Value> {
    vec![
        // Missing username
        json!({
            "userVerification": "required"
        }),
        // Empty username
        json!({
            "username": "",
            "userVerification": "required"
        }),
        // Invalid userVerification value
        json!({
            "username": "johndoe@example.com",
            "userVerification": "invalid"
        }),
        // Malformed JSON structure
        json!({
            "username": 123,
            "userVerification": "required"
        }),
    ]
}

/// Create test app instance for integration testing
pub fn create_test_app() -> actix_web::test::TestServer {
    test::start(|| {
        App::new()
            .app_data(web::Data::new(AppConfig::test_config()))
            .configure(crate::api::configure_routes)
    })
}

/// Base64url encoding/decoding utilities for tests
pub mod base64url {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    pub fn encode(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(data)
    }

    pub fn is_valid(data: &str) -> bool {
        decode(data).is_ok()
    }
}

/// Challenge generation utilities for tests
pub mod challenge {
    use rand::RngCore;

    pub fn generate_test_challenge() -> Vec<u8> {
        let mut challenge = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        challenge
    }

    pub fn generate_test_challenge_string() -> String {
        super::base64url::encode(&generate_test_challenge())
    }
}

/// Mock data generators for property-based testing
pub mod generators {
    use proptest::prelude::*;
    use crate::api::models::*;

    pub fn username_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
            .prop_map(|s| s.to_string())
    }

    pub fn display_name_strategy() -> impl Strategy<Value = String> {
        "[A-Za-z ]{3,50}".prop_map(|s| s.to_string())
    }

    pub fn attestation_strategy() -> impl Strategy<Value = String> {
        prop_oneof!["none", "indirect", "direct"].prop_map(|s| s.to_string())
    }

    pub fn user_verification_strategy() -> impl Strategy<Value = String> {
        prop_oneof!["required", "preferred", "discouraged"].prop_map(|s| s.to_string())
    }

    pub fn authenticator_attachment_strategy() -> impl Strategy<Value = String> {
        prop_oneof!["platform", "cross-platform"].prop_map(|s| s.to_string())
    }

    pub fn attestation_options_request_strategy() -> impl Strategy<Value = AttestationOptionsRequest> {
        (
            username_strategy(),
            display_name_strategy(),
            prop::option::of(authenticator_selection_strategy()),
            attestation_strategy(),
        ).prop_map(|(username, display_name, auth_selection, attestation)| {
            AttestationOptionsRequest {
                username,
                display_name,
                authenticator_selection: auth_selection,
                attestation,
            }
        })
    }

    pub fn authenticator_selection_strategy() -> impl Strategy<Value = AuthenticatorSelectionCriteria> {
        (
            prop::option::of(any::<bool>()),
            prop::option::of(authenticator_attachment_strategy()),
            prop::option::of(user_verification_strategy()),
            prop::option::of(prop_oneof!["required", "preferred", "discouraged"].prop_map(|s| s.to_string())),
        ).prop_map(|(require_resident_key, authenticator_attachment, user_verification, resident_key)| {
            AuthenticatorSelectionCriteria {
                require_resident_key,
                authenticator_attachment,
                user_verification,
                resident_key,
            }
        })
    }

    pub fn assertion_options_request_strategy() -> impl Strategy<Value = AssertionOptionsRequest> {
        (
            username_strategy(),
            prop::option::of(user_verification_strategy()),
        ).prop_map(|(username, user_verification)| {
            AssertionOptionsRequest {
                username,
                user_verification,
            }
        })
    }
}