//! FIDO2/WebAuthn request and response models

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

/// Registration request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    /// User's unique identifier (email or username)
    pub username: String,
    /// Human-readable display name for the user
    pub display_name: String,
    /// Authenticator selection criteria
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference
    pub attestation: Option<String>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// Whether a resident key is required
    pub require_resident_key: Option<bool>,
    /// Authenticator attachment preference
    pub authenticator_attachment: Option<String>,
    /// User verification requirement
    pub user_verification: Option<String>,
}

/// Registration response options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    /// Response status
    pub status: String,
    /// Error message
    pub error_message: String,
    /// Relying party information
    pub rp: PublicKeyCredentialRpEntity,
    /// User information
    pub user: ServerPublicKeyCredentialUserEntity,
    /// Generated challenge
    pub challenge: String,
    /// Supported public key algorithms
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Request timeout in milliseconds
    pub timeout: Option<u64>,
    /// Credentials to exclude from registration
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    /// Authenticator selection criteria
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation conveyance preference
    pub attestation: Option<String>,
    /// Authentication extensions
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Relying Party entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// Relying party name
    pub name: String,
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    /// Base64url-encoded user ID
    pub id: String,
    /// User's username
    pub name: String,
    /// User's display name
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// Credential type (always "public-key")
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Algorithm identifier (e.g., -7 for ES256)
    pub alg: i32,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Base64url-encoded credential ID
    pub id: String,
    /// Supported transports
    pub transports: Option<Vec<String>>,
}

/// Server public key credential (for attestation result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    /// Base64url-encoded credential ID
    pub id: String,
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Attestation response
    pub response: ServerAuthenticatorAttestationResponse,
    /// Client extension results
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    /// Base64url-encoded client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Base64url-encoded attestation object
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Authentication request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    /// User's username
    pub username: String,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Authentication response options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    /// Response status
    pub status: String,
    /// Error message
    pub error_message: String,
    /// Generated challenge
    pub challenge: String,
    /// Request timeout in milliseconds
    pub timeout: Option<u64>,
    /// Relying party ID
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Allowed credentials for authentication
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
    /// Authentication extensions
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Server public key credential (for assertion result)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialAssertion {
    /// Base64url-encoded credential ID
    pub id: String,
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Assertion response
    pub response: ServerAuthenticatorAssertionResponse,
    /// Client extension results
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    /// Base64url-encoded authenticator data
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Base64url-encoded signature
    pub signature: String,
    /// Base64url-encoded user handle
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    /// Base64url-encoded client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}