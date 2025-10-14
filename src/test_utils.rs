//! Test utilities for FIDO2/WebAuthn testing
//! 
//! This module provides common test utilities and helpers for testing
//! WebAuthn functionality.

use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Test helper for generating mock challenges
pub fn generate_test_challenge() -> String {
    use base64::Engine;
    let challenge_bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)
}

/// Test helper for generating mock user IDs
pub fn generate_test_user_id() -> String {
    use base64::Engine;
    let user_id = Uuid::new_v4().as_bytes().to_vec();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id)
}

/// Test helper for creating mock attestation objects
pub fn create_mock_attestation_object() -> String {
    // This is a simplified mock - in real tests you'd use proper CBOR encoding
    "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string()
}

/// Test helper for creating mock client data JSON
pub fn create_mock_client_data_json(challenge: &str, origin: &str, typ: &str) -> String {
    use base64::Engine;
    let client_data = serde_json::json!({
        "challenge": challenge,
        "clientExtensions": {},
        "hashAlgorithm": "SHA-256",
        "origin": origin,
        "type": typ
    });
    
    let client_data_str = serde_json::to_string(&client_data).unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data_str.as_bytes())
}

/// Test helper for creating mock authenticator data
pub fn create_mock_authenticator_data() -> String {
    "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string()
}

/// Test helper for creating mock signature
pub fn create_mock_signature() -> String {
    "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string()
}