//! Common schema types used across FIDO2/WebAuthn API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base response type for all API endpoints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    /// Status of the operation ("ok" or "failed")
    pub status: String,
    /// Error message if status is "failed", empty string otherwise
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    /// Creates a successful response
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    /// Creates an error response with the given message
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
    /// Human-readable name for the relying party
    pub name: String,
    /// Relying party identifier (domain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// User entity information with base64url encoded ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialUserEntity {
    /// Base64url encoded user identifier
    pub id: String, // base64url encoded
    /// Human-readable username
    pub name: String,
    /// Human-friendly display name for the user
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialParameters {
    /// Credential type (always "public-key")
    #[serde(rename = "type")]
    pub type_: String, // "public-key"
    /// COSE algorithm identifier
    pub alg: i32,      // COSE algorithm identifier
}

/// Credential descriptor with base64url encoded ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialDescriptor {
    /// Credential type (always "public-key")
    #[serde(rename = "type")]
    pub type_: String, // "public-key"
    /// Base64url encoded credential identifier
    pub id: String,    // base64url encoded credential ID
    /// Supported transport methods for the authenticator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    /// Authenticator attachment preference ("platform" or "cross-platform")
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>, // "platform" | "cross-platform"
    /// Whether a resident key is required
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    /// User verification requirement ("required", "preferred", or "discouraged")
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
    /// Base64url encoded client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
}

/// Public key credential with base64url encoded fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredential {
    /// Base64url encoded credential identifier
    pub id: String, // base64url encoded credential ID
    /// Base64url encoded raw credential ID
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>, // base64url encoded
    /// Authenticator response (either attestation or assertion)
    pub response: serde_json::Value, // Either attestation or assertion response
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