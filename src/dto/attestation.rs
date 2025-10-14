use serde::{Deserialize, Serialize};
use super::common::*;

/// Request for /attestation/options endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String, // "none" | "indirect" | "direct"
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Response for /attestation/options endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String, // base64url encoded
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", default)]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authenticator Attestation Response (server format with base64url encoding)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
    #[serde(rename = "attestationObject")]
    pub attestation_object: String, // base64url encoded
}

/// Public Key Credential for attestation result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String, // base64url encoded credential ID
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>, // base64url encoded raw ID
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults", default)]
    pub get_client_extension_results: AuthenticationExtensionsClientOutputs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Request for /attestation/result endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResultRequest {
    #[serde(flatten)]
    pub credential: ServerPublicKeyCredential,
}

/// Response for /attestation/result endpoint
pub type AttestationResultResponse = ServerResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_attestation_options_request_deserialization() {
        let json = r#"{
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }"#;

        let request: ServerPublicKeyCredentialCreationOptionsRequest = 
            serde_json::from_str(json).unwrap();
        
        assert_eq!(request.username, "johndoe@example.com");
        assert_eq!(request.display_name, "John Doe");
        assert_eq!(request.attestation, "direct");
        
        let auth_selection = request.authenticator_selection.unwrap();
        assert_eq!(auth_selection.require_resident_key, Some(false));
        assert_eq!(auth_selection.authenticator_attachment, Some("cross-platform".to_string()));
        assert_eq!(auth_selection.user_verification, Some("preferred".to_string()));
    }

    #[test]
    fn test_attestation_options_request_default_attestation() {
        let json = r#"{
            "username": "johndoe@example.com",
            "displayName": "John Doe"
        }"#;

        let request: ServerPublicKeyCredentialCreationOptionsRequest = 
            serde_json::from_str(json).unwrap();
        
        assert_eq!(request.attestation, "none");
    }

    #[test]
    fn test_attestation_options_response_serialization() {
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            base: ServerResponse::ok(),
            rp: PublicKeyCredentialRpEntity {
                name: "Example Corporation".to_string(),
                id: Some("example.com".to_string()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: "S3932ee31vKEC0JtJMIQ".to_string(),
                name: "johndoe@example.com".to_string(),
                display_name: "John Doe".to_string(),
            },
            challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    credential_type: "public-key".to_string(),
                    alg: -7,
                }
            ],
            timeout: Some(10000),
            exclude_credentials: vec![
                ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: "opQf1WmYAa5aupUKJIQp".to_string(),
                    transports: None,
                }
            ],
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some("cross-platform".to_string()),
                user_verification: Some("preferred".to_string()),
                resident_key: None,
            }),
            attestation: "direct".to_string(),
            extensions: None,
        };

        let json = serde_json::to_string_pretty(&response).unwrap();
        println!("Actual JSON: {}", json);
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"challenge\":\"uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN\""));
        assert!(json.contains("\"pubKeyCredParams\""));
        assert!(json.contains("\"excludeCredentials\""));
    }

    #[test]
    fn test_attestation_result_request_deserialization() {
        let json = r#"{
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }"#;

        let request: AttestationResultRequest = serde_json::from_str(json).unwrap();
        
        assert_eq!(request.credential.id, "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA");
        assert_eq!(request.credential.credential_type, "public-key");
        assert!(!request.credential.response.client_data_json.is_empty());
        assert!(!request.credential.response.attestation_object.is_empty());
    }

    #[test]
    fn test_invalid_username_validation() {
        let json = r#"{
            "username": "",
            "displayName": "John Doe"
        }"#;

        let request: Result<ServerPublicKeyCredentialCreationOptionsRequest, _> = 
            serde_json::from_str(json);
        
        // Should deserialize but validation should happen at service layer
        assert!(request.is_ok());
        let req = request.unwrap();
        assert_eq!(req.username, "");
    }

    #[test]
    fn test_missing_required_fields() {
        let json = r#"{
            "displayName": "John Doe"
        }"#;

        let request: Result<ServerPublicKeyCredentialCreationOptionsRequest, _> = 
            serde_json::from_str(json);
        
        assert!(request.is_err());
    }
}