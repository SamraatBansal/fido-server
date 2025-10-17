//! WebAuthn data types for FIDO2 conformance

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    /// Response status ("ok" or "failed")
    pub status: String,
    /// Error message (empty if status is "ok")
    #[serde(rename = "errorMessage")]
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

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// Whether a resident key is required
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    /// Authenticator attachment preference
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// No attestation
    None,
    /// Indirect attestation
    Indirect,
    /// Direct attestation
    Direct,
}

impl Default for AttestationConveyancePreference {
    fn default() -> Self {
        AttestationConveyancePreference::None
    }
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Algorithm identifier
    pub alg: i64,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Credential ID
    pub id: String,
    /// Supported transports
    pub transports: Option<Vec<String>>,
}

/// Public key credential user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    /// User ID
    pub id: String,
    /// User name
    pub name: String,
    /// Display name
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// RP name
    pub name: String,
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    /// Extension inputs
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Request for credential creation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    /// Username
    pub username: String,
    /// Display name
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// Authenticator selection criteria
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation preference
    #[serde(default)]
    pub attestation: AttestationConveyancePreference,
}

/// Response for credential creation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    /// Base response
    #[serde(flatten)]
    pub base: ServerResponse,
    /// Relying party
    pub rp: PublicKeyCredentialRpEntity,
    /// User entity
    pub user: ServerPublicKeyCredentialUserEntity,
    /// Challenge
    pub challenge: String,
    /// Public key credential parameters
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout
    pub timeout: Option<u64>,
    /// Exclude credentials
    #[serde(default, rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    /// Authenticator selection
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Attestation
    pub attestation: Option<AttestationConveyancePreference>,
    /// Extensions
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Server authenticator response base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorResponse {
    /// Client data
    #[serde(flatten)]
    pub client_data: serde_json::Value,
}

/// Server authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    /// Client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Attestation object
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Server authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    /// Authenticator data
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature
    pub signature: String,
    /// User handle
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    /// Client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Server public key credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    /// Credential ID
    pub id: String,
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Response data
    pub response: serde_json::Value,
    /// Client extension results
    #[serde(rename = "getClientExtensionResults")]
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Request for credential get options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    /// Username
    pub username: String,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Response for credential get options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    /// Base response
    #[serde(flatten)]
    pub base: ServerResponse,
    /// Challenge
    pub challenge: String,
    /// Timeout
    pub timeout: Option<u64>,
    /// Relying party ID
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Allow credentials
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    /// User verification
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
    /// Extensions
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}