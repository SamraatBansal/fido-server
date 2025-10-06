//! Authentication request/response schemas

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::{UserVerificationPolicy, AuthenticatorAttachment};

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Credential ID (base64url encoded)
    pub id: String,
    /// Transports
    pub transports: Option<Vec<String>>,
}

impl PublicKeyCredentialDescriptor {
    /// Create a new descriptor
    pub fn new(id: String, transports: Option<Vec<String>>) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            id,
            transports,
        }
    }
}

/// Authentication extensions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationExtensions {
    /// Credential properties extension
    #[serde(rename = "credProps")]
    pub cred_props: Option<bool>,
    /// Large blob extension
    #[serde(rename = "largeBlob")]
    pub large_blob: Option<AuthenticationExtensionsLargeBlob>,
    /// User verification method extension
    #[serde(rename = "uvm")]
    pub uvm: Option<bool>,
}

/// Large blob authentication extension
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsLargeBlob {
    /// Support for large blob
    pub support: Option<String>,
    /// Read operation
    pub read: Option<bool>,
    /// Write operation
    pub write: Option<bool>,
}

/// Public key credential request options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialRequestOptions {
    /// Challenge (base64url encoded)
    pub challenge: String,
    /// Allow credentials
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationPolicy,
    /// Timeout in milliseconds
    pub timeout: u32,
    /// Extensions
    pub extensions: Option<AuthenticationExtensions>,
    /// Relying party ID
    #[serde(rename = "rpId")]
    pub rp_id: String,
}

/// Authentication start request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationStartRequest {
    /// Username
    pub username: String,
    /// User verification policy
    #[serde(default = "UserVerificationPolicy::default")]
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationPolicy,
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

/// Authentication start response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationStartResponse {
    /// Public key credential request options
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialRequestOptions,
}

/// Authentication finish response data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationFinishResponseData {
    /// Client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Authenticator data
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature
    pub signature: String,
    /// User handle
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// Authentication finish request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationFinishRequest {
    /// Credential ID
    pub id: String,
    /// Raw ID
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Response data
    pub response: AuthenticationFinishResponseData,
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    /// Client extension results
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
    /// Type
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Authentication finish response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationFinishResponse {
    /// Status
    pub status: String,
    /// User ID
    #[serde(rename = "userId")]
    pub user_id: String,
    /// New signature counter
    #[serde(rename = "newSignCount")]
    pub new_sign_count: u64,
    /// Credential ID
    #[serde(rename = "credentialId")]
    pub credential_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_start_request_serialization() {
        let request = AuthenticationStartRequest {
            username: "test@example.com".to_string(),
            user_verification: UserVerificationPolicy::Required,
            authenticator_attachment: Some(AuthenticatorAttachment::Platform),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: AuthenticationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_public_key_credential_descriptor() {
        let descriptor = PublicKeyCredentialDescriptor::new(
            "credential-id".to_string(),
            Some(vec!["usb".to_string(), "nfc".to_string()]),
        );

        assert_eq!(descriptor.id, "credential-id");
        assert_eq!(descriptor.cred_type, "public-key");
        assert_eq!(descriptor.transports, Some(vec!["usb".to_string(), "nfc".to_string()]));
    }

    #[test]
    fn test_public_key_credential_request_options() {
        let options = PublicKeyCredentialRequestOptions {
            challenge: "challenge".to_string(),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor::new(
                "cred-id".to_string(),
                None,
            )]),
            user_verification: UserVerificationPolicy::Preferred,
            timeout: 60000,
            extensions: None,
            rp_id: "example.com".to_string(),
        };

        assert_eq!(options.challenge, "challenge");
        assert_eq!(options.user_verification, UserVerificationPolicy::Preferred);
        assert_eq!(options.rp_id, "example.com");
    }

    #[test]
    fn test_authentication_finish_request() {
        let request = AuthenticationFinishRequest {
            id: "credential-id".to_string(),
            raw_id: "raw-id".to_string(),
            response: AuthenticationFinishResponseData {
                client_data_json: "client-data".to_string(),
                authenticator_data: "authenticator-data".to_string(),
                signature: "signature".to_string(),
                user_handle: Some("user-handle".to_string()),
            },
            authenticator_attachment: Some("platform".to_string()),
            client_extension_results: None,
            cred_type: "public-key".to_string(),
        };

        assert_eq!(request.id, "credential-id");
        assert_eq!(request.response.client_data_json, "client-data");
        assert_eq!(request.response.signature, "signature");
        assert_eq!(request.cred_type, "public-key");
    }

    #[test]
    fn test_authentication_extensions() {
        let extensions = AuthenticationExtensions {
            cred_props: Some(true),
            large_blob: Some(AuthenticationExtensionsLargeBlob {
                support: Some("required".to_string()),
                read: Some(true),
                write: Some(false),
            }),
            uvm: Some(true),
        };

        assert_eq!(extensions.cred_props, Some(true));
        assert_eq!(extensions.uvm, Some(true));
        assert!(extensions.large_blob.is_some());
    }

    #[test]
    fn test_authentication_finish_response() {
        let response = AuthenticationFinishResponse {
            status: "success".to_string(),
            user_id: "user-123".to_string(),
            new_sign_count: 42,
            credential_id: "credential-id".to_string(),
        };

        assert_eq!(response.status, "success");
        assert_eq!(response.user_id, "user-123");
        assert_eq!(response.new_sign_count, 42);
        assert_eq!(response.credential_id, "credential-id");
    }
}