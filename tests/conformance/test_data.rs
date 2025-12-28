/// Test Data Generation for FIDO2 Conformance Tests
/// 
/// This module provides comprehensive test data generators for all FIDO2 conformance test scenarios.
/// Data includes both valid (positive tests) and invalid (negative tests) examples.

use base64::prelude::*;
use serde_json::{json, Value};
use uuid::Uuid;
use webauthn_rs_proto::*;

/// Generate valid ServerPublicKeyCredentialCreationOptionsRequest
pub fn valid_creation_options_request() -> Value {
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

/// Generate invalid creation options requests for negative testing
pub fn invalid_creation_options_requests() -> Vec<(String, Value)> {
    vec![
        ("missing_username".to_string(), json!({
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })),
        ("empty_username".to_string(), json!({
            "username": "",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })),
        ("missing_display_name".to_string(), json!({
            "username": "johndoe@example.com",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        })),
        ("invalid_attestation".to_string(), json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "invalid_value"
        })),
    ]
}

/// Generate valid ServerPublicKeyCredentialCreationOptionsResponse
pub fn valid_creation_options_response() -> Value {
    json!({
        "status": "ok",
        "errorMessage": "",
        "rp": {
            "name": "Example Corporation",
            "id": "example.com"
        },
        "user": {
            "id": "S3932ee31vKEC0JtJMIQ",
            "name": "johndoe@example.com",
            "displayName": "John Doe"
        },
        "challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7
            },
            {
                "type": "public-key", 
                "alg": -257
            }
        ],
        "timeout": 10000,
        "excludeCredentials": [
            {
                "type": "public-key",
                "id": "opQf1WmYAa5aupUKJIQp"
            }
        ],
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    })
}

/// Generate valid ServerAuthenticatorAttestationResponse with packed attestation
pub fn valid_packed_attestation_response() -> Value {
    json!({
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    })
}

/// Generate none attestation response
pub fn valid_none_attestation_response() -> Value {
    json!({
        "id": "AaFdkcTKTWICrT97LZLqj7fL2mZ3Qat5C0Nq_5X1SdM6aXMaXYKU8mH_1z8LLg6b",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY3QxY0hEeFlzbEQtNTlrRklKYTY5Y3Z5Sk9qaDlLLVZpbGdJVXJEc21LTSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAALraVWanqkAfvZZiABaOaONdAEABoV2RxMpNYgKtP3stkuqPt8vaZndBq3kLQ2r_lfVJ0zppcxpdgpTyYf_XPwsuDpulAQIDJiABIVggh8DJAH6HYHU7w9_cqIdP7ZJYx-CZdSaYVW2BKYsT8EoiWCAC6xJVKxYyh_0cMFg_N5yAqD0kBJqhYqWgVZZJ8u7n2Q"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    })
}

/// Generate FIDO U2F attestation response
pub fn valid_fido_u2f_attestation_response() -> Value {
    json!({
        "id": "aHi4QqKzPUbNL2ZRw8qhZJy8XdB-YNjK0Gn4jXfxpF-Q_jR8F3e4x5xp9-YWANcB",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibGJZRGIzbFJPYXZERkJLT09SUnFQbWNWY1J5SU10d0p6RkRfYlF3blpIQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYJAgqnKZ1k-b5npLxzM-WF0nEL4ROK5g1UpT_y4zBzTjw"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    })
}

/// Generate valid assertion options request
pub fn valid_assertion_options_request() -> Value {
    json!({
        "username": "johndoe@example.com",
        "userVerification": "required"
    })
}

/// Generate invalid assertion options requests
pub fn invalid_assertion_options_requests() -> Vec<(String, Value)> {
    vec![
        ("missing_username".to_string(), json!({
            "userVerification": "required"
        })),
        ("empty_username".to_string(), json!({
            "username": "",
            "userVerification": "required"
        })),
        ("invalid_user_verification".to_string(), json!({
            "username": "johndoe@example.com",
            "userVerification": "invalid_value"
        })),
    ]
}

/// Generate valid assertion options response
pub fn valid_assertion_options_response() -> Value {
    json!({
        "status": "ok",
        "errorMessage": "",
        "challenge": "6283u0svT-YIF3pSolzkQHStwkJCaLKx",
        "timeout": 20000,
        "rpId": "example.com",
        "allowCredentials": [
            {
                "id": "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m",
                "type": "public-key",
                "transports": ["usb", "nfc"]
            }
        ],
        "userVerification": "required"
    })
}

/// Generate valid assertion response
pub fn valid_assertion_response() -> Value {
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

/// Generate malformed client data JSON for negative tests
pub fn malformed_client_data_json_cases() -> Vec<(String, String)> {
    vec![
        ("invalid_base64".to_string(), "not-valid-base64!@#$%".to_string()),
        ("empty_string".to_string(), "".to_string()),
        ("non_json_base64".to_string(), BASE64_STANDARD.encode("not json data")),
        ("missing_type".to_string(), BASE64_STANDARD.encode(r#"{"challenge":"test","origin":"http://localhost:3000"}"#)),
        ("missing_challenge".to_string(), BASE64_STANDARD.encode(r#"{"type":"webauthn.create","origin":"http://localhost:3000"}"#)),
        ("missing_origin".to_string(), BASE64_STANDARD.encode(r#"{"type":"webauthn.create","challenge":"test"}"#)),
        ("wrong_type".to_string(), BASE64_STANDARD.encode(r#"{"type":"wrong.type","challenge":"test","origin":"http://localhost:3000"}"#)),
    ]
}

/// Generate malformed attestation object cases
pub fn malformed_attestation_object_cases() -> Vec<(String, String)> {
    vec![
        ("invalid_base64".to_string(), "not-valid-base64!@#$%".to_string()),
        ("empty_string".to_string(), "".to_string()),
        ("invalid_cbor".to_string(), BASE64_STANDARD.encode("not cbor data")),
        ("missing_fmt".to_string(), BASE64_STANDARD.encode(&[0xa1, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x41, 0x00])), // CBOR without fmt
    ]
}

/// Generate challenge test cases
pub fn challenge_test_cases() -> Vec<(String, String, bool)> {
    vec![
        ("valid_challenge".to_string(), generate_base64_challenge(32), true),
        ("minimum_length".to_string(), generate_base64_challenge(16), true),
        ("maximum_length".to_string(), generate_base64_challenge(64), true),
        ("too_short".to_string(), generate_base64_challenge(8), false),
        ("too_long".to_string(), generate_base64_challenge(128), false),
        ("empty_challenge".to_string(), "".to_string(), false),
        ("invalid_base64".to_string(), "not-valid-base64!@#$%".to_string(), false),
    ]
}

/// Generate a base64url encoded challenge of specified byte length
pub fn generate_base64_challenge(byte_length: usize) -> String {
    let bytes: Vec<u8> = (0..byte_length).map(|i| (i % 256) as u8).collect();
    BASE64_URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate test user ID
pub fn generate_test_user_id() -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

/// Generate test credential ID
pub fn generate_test_credential_id() -> String {
    let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    BASE64_URL_SAFE_NO_PAD.encode(&bytes)
}

/// Standard error responses for negative tests
pub fn standard_error_responses() -> Vec<(String, Value)> {
    vec![
        ("missing_field".to_string(), json!({
            "status": "failed",
            "errorMessage": "Missing required field"
        })),
        ("invalid_format".to_string(), json!({
            "status": "failed", 
            "errorMessage": "Invalid data format"
        })),
        ("validation_failed".to_string(), json!({
            "status": "failed",
            "errorMessage": "Validation failed"
        })),
        ("signature_verification_failed".to_string(), json!({
            "status": "failed",
            "errorMessage": "Can not validate response signature!"
        })),
    ]
}
