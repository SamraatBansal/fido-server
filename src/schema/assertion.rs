//! Assertion (Authentication) schema types

use serde::{Deserialize, Serialize};
use super::common::*;

/// Request for creating assertion options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    /// Username for authentication
    pub username: String,
    /// User verification requirement ("required", "preferred", or "discouraged")
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>, // "required" | "preferred" | "discouraged"
}

/// Response for assertion options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    /// Base response with status and error message
    #[serde(flatten)]
    pub base: ServerResponse,
    /// Base64url encoded challenge
    pub challenge: String, // base64url encoded
    /// Relying party identifier
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Allowed credentials for authentication
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    /// Timeout for the operation in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// User verification requirement
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    /// Client extension inputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerAuthenticatorAssertionResponse {
    /// Base authenticator response with client data
    #[serde(flatten)]
    pub base: ServerAuthenticatorResponse,
    /// Base64url encoded authenticator data
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String, // base64url encoded
    /// Base64url encoded assertion signature
    pub signature: String,          // base64url encoded
    /// Base64url encoded user handle
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>, // base64url encoded
}

/// Public key credential for assertion result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionPublicKeyCredential {
    /// Base64url encoded credential identifier
    pub id: String, // base64url encoded credential ID
    /// Base64url encoded raw credential ID
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>, // base64url encoded
    /// Assertion response from the authenticator
    pub response: ServerAuthenticatorAssertionResponse,
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
    fn test_assertion_options_request_serialization() {
        let request = ServerPublicKeyCredentialGetOptionsRequest {
            username: "alice".to_string(),
            user_verification: Some("preferred".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"username\":\"alice\""));
        assert!(json.contains("\"userVerification\":\"preferred\""));
    }

    #[test]
    fn test_assertion_options_response_serialization() {
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            base: ServerResponse::ok(),
            challenge: "BASE64URLSTRING".to_string(),
            rp_id: "example.com".to_string(),
            allow_credentials: Some(vec![ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: "BASE64URL".to_string(),
                transports: None,
            }]),
            timeout: Some(60000),
            user_verification: Some("preferred".to_string()),
            extensions: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"challenge\":\"BASE64URLSTRING\""));
        assert!(json.contains("\"rpId\":\"example.com\""));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_assertion_credential_deserialization() {
        let json = r#"{
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "type": "public-key"
        }"#;

        let credential: AssertionPublicKeyCredential = serde_json::from_str(json).unwrap();
        assert_eq!(credential.type_, "public-key");
        assert!(!credential.response.authenticator_data.is_empty());
        assert!(!credential.response.signature.is_empty());
        assert!(!credential.response.base.client_data_json.is_empty());
    }

    #[test]
    fn test_assertion_options_request_minimal() {
        let request = ServerPublicKeyCredentialGetOptionsRequest {
            username: "alice".to_string(),
            user_verification: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"username\":\"alice\""));
        assert!(!json.contains("userVerification"));
    }
}