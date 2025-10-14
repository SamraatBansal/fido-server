//! Attestation (Registration) schema types

use serde::{Deserialize, Serialize};
use super::common::*;

/// Request for creating attestation options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    /// Username for the credential
    pub username: String,
    /// Human-friendly display name for the user
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Authenticator selection criteria
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference ("none", "indirect", or "direct")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>, // "none" | "indirect" | "direct"
}

/// Response for attestation options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    /// Base response with status and error message
    #[serde(flatten)]
    pub base: ServerResponse,
    /// Relying party information
    pub rp: PublicKeyCredentialRpEntity,
    /// User information
    pub user: ServerPublicKeyCredentialUserEntity,
    /// Base64url encoded challenge
    pub challenge: String, // base64url encoded
    /// Supported public key credential parameters
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout for the operation in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// Credentials to exclude from creation
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    /// Authenticator selection criteria
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// Client extension inputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerAuthenticatorAttestationResponse {
    /// Base authenticator response with client data
    #[serde(flatten)]
    pub base: ServerAuthenticatorResponse,
    /// Base64url encoded attestation object
    #[serde(rename = "attestationObject")]
    pub attestation_object: String, // base64url encoded
}

/// Public key credential for attestation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationPublicKeyCredential {
    /// Base64url encoded credential identifier
    pub id: String, // base64url encoded credential ID
    /// Base64url encoded raw credential ID
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>, // base64url encoded
    /// Attestation response from the authenticator
    pub response: ServerAuthenticatorAttestationResponse,
    /// Credential type (always "public-key")
    #[serde(rename = "type")]
    pub type_: String, // "public-key"
    /// Client extension results
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_options_request_serialization() {
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "alice".to_string(),
            display_name: "Alice Smith".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
            }),
            attestation: Some("direct".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"username\":\"alice\""));
        assert!(json.contains("\"displayName\":\"Alice Smith\""));
        assert!(json.contains("\"attestation\":\"direct\""));
    }

    #[test]
    fn test_attestation_options_response_serialization() {
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            base: ServerResponse::ok(),
            rp: PublicKeyCredentialRpEntity {
                name: "Example RP".to_string(),
                id: Some("example.com".to_string()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: "BASE64URL".to_string(),
                name: "alice".to_string(),
                display_name: "Alice Smith".to_string(),
            },
            challenge: "BASE64URLSTRING".to_string(),
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7,
            }],
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: Some("direct".to_string()),
            extensions: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"challenge\":\"BASE64URLSTRING\""));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_attestation_credential_deserialization() {
        let json = r#"{
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "type": "public-key"
        }"#;

        let credential: AttestationPublicKeyCredential = serde_json::from_str(json).unwrap();
        assert_eq!(credential.type_, "public-key");
        assert!(!credential.response.attestation_object.is_empty());
        assert!(!credential.response.base.client_data_json.is_empty());
    }
}