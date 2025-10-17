//! WebAuthn data models for FIDO2 conformance

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    /// Response status ("ok" or "failed")
    pub status: String,
    /// Error message (empty if status is "ok")
    pub error_message: String,
}

impl ServerResponse {
    /// Create a successful response
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    /// Create an error response
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }
}

/// Registration request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    /// Username for the user
    pub username: String,
    /// Display name for the user
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Authenticator selection criteria
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference
    pub attestation: Option<String>,
}

/// Registration response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    /// Response status ("ok" or "failed")
    pub status: String,
    /// Error message (empty if status is "ok")
    pub error_message: String,
    /// Relying party information
    pub rp: PublicKeyCredentialRpEntity,
    /// User information
    pub user: ServerPublicKeyCredentialUserEntity,
    /// Generated challenge
    pub challenge: String,
    /// Public key credential parameters
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout in milliseconds
    pub timeout: Option<u32>,
    /// Credentials to exclude from registration
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    /// Authenticator selection criteria
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference
    pub attestation: Option<String>,
    /// Authentication extensions
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Authentication request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    /// Username for authentication
    pub username: String,
    /// User verification requirement
    pub user_verification: Option<String>,
}

/// Authentication response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    /// Response status ("ok" or "failed")
    pub status: String,
    /// Error message (empty if status is "ok")
    pub error_message: String,
    /// Generated challenge
    pub challenge: String,
    /// Timeout in milliseconds
    pub timeout: Option<u32>,
    /// Relying party ID
    pub rp_id: String,
    /// Allowed credentials for authentication
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    /// User verification requirement
    pub user_verification: Option<String>,
    /// Authentication extensions
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// RP entity structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// RP name
    pub name: String,
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    /// User ID (base64url encoded)
    pub id: String,
    /// Username
    #[serde(rename = "name")]
    pub name: String,
    /// Display name
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// Credential type
    #[serde(rename = "type")]
    pub type_field: String,
    /// Algorithm identifier
    pub alg: i32,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub type_field: String,
    /// Credential ID (base64url encoded)
    pub id: String,
    /// Supported transports
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// Require resident key
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Server public key credential (for attestation/result and assertion/result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    /// Credential ID
    pub id: String,
    /// Authenticator response
    pub response: ServerAuthenticatorResponse,
    /// Client extension results
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
    /// Credential type
    #[serde(rename = "type")]
    pub type_field: String,
}

/// Authenticator response (union type)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    /// Attestation response (registration)
    Attestation(ServerAuthenticatorAttestationResponse),
    /// Assertion response (authentication)
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    /// Client data JSON (base64url encoded)
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Attestation object (base64url encoded)
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    /// Authenticator data (base64url encoded)
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature (base64url encoded)
    pub signature: String,
    /// User handle (base64url encoded)
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    /// Client data JSON (base64url encoded)
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}