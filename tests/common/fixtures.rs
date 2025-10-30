//! Test data fixtures

use serde_json::{json, Value};
use fido_server::models::{
    ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredential, ServerAuthenticatorResponse, ServerAuthenticatorAttestationResponse,
    ServerAuthenticatorAssertionResponse,
};

/// Create a valid registration options request
pub fn create_valid_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: Some(webauthn_rs::proto::AuthenticatorSelectionCriteria {
            require_resident_key: false,
            authenticator_attachment: Some(webauthn_rs::proto::AuthenticatorAttachment::CrossPlatform),
            user_verification: webauthn_rs::proto::UserVerificationPolicy::Preferred,
        }),
        attestation: Some(webauthn_rs::proto::AttestationConveyancePreference::Direct),
    }
}

/// Create a valid authentication options request
pub fn create_valid_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
    ServerPublicKeyCredentialGetOptionsRequest {
        username: "test@example.com".to_string(),
        user_verification: Some(webauthn_rs::proto::UserVerificationPolicy::Preferred),
    }
}

/// Create an empty username request (invalid)
pub fn create_empty_username_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
    }
}

/// Create an oversized display name request (invalid)
pub fn create_oversized_display_name_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "a".repeat(256), // Too long
        authenticator_selection: None,
        attestation: None,
    }
}

/// Create a mock registration credential response
pub fn create_mock_registration_request(challenge: &str) -> ServerPublicKeyCredential {
    ServerPublicKeyCredential {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        credential_type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
            client_data_json: create_mock_client_data_json(challenge, "webauthn.create"),
            attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
        }),
        get_client_extension_results: None,
    }
}

/// Create a mock authentication credential response
pub fn create_mock_authentication_request(challenge: &str) -> ServerPublicKeyCredential {
    ServerPublicKeyCredential {
        id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
        credential_type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Assertion(ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: create_mock_client_data_json(challenge, "webauthn.get"),
        }),
        get_client_extension_results: None,
    }
}

/// Create mock client data JSON
fn create_mock_client_data_json(challenge: &str, typ: &str) -> String {
    let client_data = json!({
        "challenge": challenge,
        "clientExtensions": {},
        "hashAlgorithm": "SHA-256",
        "origin": "http://localhost:8080",
        "type": typ
    });
    
    base64::encode_config(client_data.to_string().as_bytes(), base64::URL_SAFE_NO_PAD)
}

/// Create malformed JSON data for testing
pub fn create_malformed_json() -> Value {
    json!({
        "username": "",
        "displayName": "",
        "invalidField": "test"
    })
}

/// Create oversized request data
pub fn create_oversized_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
    ServerPublicKeyCredentialCreationOptionsRequest {
        username: "a".repeat(300), // Too long
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: None,
    }
}