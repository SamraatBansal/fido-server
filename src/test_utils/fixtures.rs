use crate::schema::{
    AttestationOptionsRequest, AssertionOptionsRequest, AttestationResultRequest, 
    AssertionResultRequest, AttestationResponse, AssertionResponse,
    AuthenticatorSelectionCriteria, AttestationConveyancePreference,
    AuthenticatorAttachment, UserVerificationRequirement
};

/// Test fixtures for FIDO2 conformance testing
pub struct TestFixtures;

impl TestFixtures {
    /// Valid attestation options request matching the conformance test specification
    pub fn valid_attestation_options_request() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
                user_verification: Some(UserVerificationRequirement::Preferred),
            }),
            attestation: AttestationConveyancePreference::Direct,
        }
    }

    /// Valid assertion options request
    pub fn valid_assertion_options_request() -> AssertionOptionsRequest {
        AssertionOptionsRequest {
            username: "johndoe@example.com".to_string(),
            user_verification: Some(UserVerificationRequirement::Preferred),
        }
    }

    /// Valid attestation result request with real test data
    pub fn valid_attestation_result_request() -> AttestationResultRequest {
        AttestationResultRequest {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: None,
            response: AttestationResponse {
                client_data_json: "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9".to_string(),
                attestation_object: "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI".to_string(),
            },
            credential_type: "public-key".to_string(),
            client_extension_results: Some(serde_json::json!({})),
        }
    }

    /// Valid assertion result request with real test data
    pub fn valid_assertion_result_request() -> AssertionResultRequest {
        AssertionResultRequest {
            id: "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA".to_string(),
            raw_id: None,
            response: AssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: Some("".to_string()),
                client_data_json: "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9".to_string(),
            },
            credential_type: "public-key".to_string(),
            client_extension_results: Some(serde_json::json!({})),
        }
    }

    /// Invalid requests for negative testing
    pub fn invalid_attestation_options_request_empty_username() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: "".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: AttestationConveyancePreference::None,
        }
    }

    pub fn invalid_attestation_options_request_invalid_email() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: "invalid-email".to_string(),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: AttestationConveyancePreference::None,
        }
    }

    pub fn invalid_attestation_options_request_too_long_username() -> AttestationOptionsRequest {
        AttestationOptionsRequest {
            username: "x".repeat(256),
            display_name: "John Doe".to_string(),
            authenticator_selection: None,
            attestation: AttestationConveyancePreference::None,
        }
    }

    pub fn invalid_assertion_options_request_empty_username() -> AssertionOptionsRequest {
        AssertionOptionsRequest {
            username: "".to_string(),
            user_verification: None,
        }
    }

    pub fn invalid_attestation_result_request_empty_id() -> AttestationResultRequest {
        let mut req = Self::valid_attestation_result_request();
        req.id = "".to_string();
        req
    }

    pub fn invalid_attestation_result_request_invalid_base64() -> AttestationResultRequest {
        let mut req = Self::valid_attestation_result_request();
        req.response.client_data_json = "invalid-base64!@#$".to_string();
        req
    }

    pub fn invalid_assertion_result_request_empty_signature() -> AssertionResultRequest {
        let mut req = Self::valid_assertion_result_request();
        req.response.signature = "".to_string();
        req
    }

    /// Test challenge values
    pub fn valid_challenge() -> String {
        "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string()
    }

    pub fn expired_challenge() -> String {
        "expired-challenge-value".to_string()
    }

    pub fn used_challenge() -> String {
        "used-challenge-value".to_string()
    }

    /// Test user IDs
    pub fn valid_user_id() -> String {
        "S3932ee31vKEC0JtJMIQ".to_string()
    }

    /// Test credential IDs
    pub fn valid_credential_id() -> String {
        "opQf1WmYAa5aupUKJIQp".to_string()
    }
}