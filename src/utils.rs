use base64urlsafedata::Base64UrlSafeData;
use crate::error::{AppError, AppResult};

pub fn decode_base64url(input: &str) -> AppResult<Vec<u8>> {
    Base64UrlSafeData::try_from(input)
        .map(|data| data.into())
        .map_err(|e| AppError::InvalidRequest(format!("Invalid base64url: {}", e)))
}

pub fn encode_base64url(input: &[u8]) -> String {
    Base64UrlSafeData::from(input).to_string()
}

pub fn validate_username(username: &str) -> AppResult<()> {
    if username.is_empty() {
        return Err(AppError::InvalidRequest("Username cannot be empty".to_string()));
    }
    if username.len() > 255 {
        return Err(AppError::InvalidRequest("Username too long".to_string()));
    }
    Ok(())
}

pub fn validate_display_name(display_name: &str) -> AppResult<()> {
    if display_name.is_empty() {
        return Err(AppError::InvalidRequest("Display name cannot be empty".to_string()));
    }
    if display_name.len() > 255 {
        return Err(AppError::InvalidRequest("Display name too long".to_string()));
    }
    Ok(())
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::models::*;
    use crate::config::AppConfig;

    pub fn create_test_config() -> AppConfig {
        AppConfig::for_testing()
    }

    pub fn create_test_registration_request() -> ServerPublicKeyCredentialCreationOptionsRequest {
        ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some(webauthn_rs_proto::AuthenticatorAttachment::CrossPlatform),
                user_verification: Some(webauthn_rs_proto::UserVerificationPolicy::Preferred),
                resident_key: None,
            }),
            attestation: webauthn_rs_proto::AttestationConveyancePreference::Direct,
        }
    }

    pub fn create_test_authentication_request() -> ServerPublicKeyCredentialGetOptionsRequest {
        ServerPublicKeyCredentialGetOptionsRequest {
            username: "test@example.com".to_string(),
            user_verification: Some(webauthn_rs_proto::UserVerificationPolicy::Preferred),
        }
    }

    pub fn create_mock_attestation_credential() -> ServerPublicKeyCredential {
        ServerPublicKeyCredential {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: Some("LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string()),
            response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
                client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
                attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
            }),
            type_: "public-key".to_string(),
            get_client_extension_results: Some(serde_json::json!({})),
        }
    }

    pub fn create_mock_assertion_credential() -> ServerPublicKeyCredential {
        ServerPublicKeyCredential {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: Some("LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string()),
            response: ServerAuthenticatorResponse::Assertion(ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
                signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: Some("".to_string()),
            }),
            type_: "public-key".to_string(),
            get_client_extension_results: Some(serde_json::json!({})),
        }
    }
}