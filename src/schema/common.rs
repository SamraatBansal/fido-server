//! Common schema types used across FIDO2/WebAuthn API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base response type for all API endpoints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

/// Relying Party entity information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// User entity information with base64url encoded ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String, // base64url encoded
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_: String, // "public-key"
    pub alg: i32,      // COSE algorithm identifier
}

/// Credential descriptor with base64url encoded ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String, // "public-key"
    pub id: String,    // base64url encoded credential ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>, // "platform" | "cross-platform"
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>, // "required" | "preferred" | "discouraged"
}

/// Client extension results
pub type AuthenticationExtensionsClientOutputs = HashMap<String, serde_json::Value>;

/// Client extension inputs
pub type AuthenticationExtensionsClientInputs = HashMap<String, serde_json::Value>;

/// Base authenticator response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerAuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
}

/// Public key credential with base64url encoded fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredential {
    pub id: String, // base64url encoded credential ID
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>, // base64url encoded
    pub response: serde_json::Value, // Either attestation or assertion response
    #[serde(rename = "type")]
    pub type_: String, // "public-key"
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_response_ok() {
        let response = ServerResponse::ok();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[test]
    fn test_server_response_error() {
        let response = ServerResponse::error("Test error");
        assert_eq!(response.status, "failed");
        assert_eq!(response.error_message, "Test error");
    }

    #[test]
    fn test_server_response_serialization() {
        let response = ServerResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"errorMessage\":\"\""));
    }
}