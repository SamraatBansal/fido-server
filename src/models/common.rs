//! Common models and types used across FIDO2 operations

use serde::{Deserialize, Serialize};

/// Standard server response format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

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
    pub require_resident_key: bool,
    pub authenticator_attachment: Option<String>,
    pub user_verification: String,
}

impl Default for AuthenticatorSelectionCriteria {
    fn default() -> Self {
        Self {
            require_resident_key: false,
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: "preferred".to_string(),
        }
    }
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Relying party entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Server public key credential (base)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: serde_json::Value,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
}

/// Server authenticator response base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
}

impl Default for AttestationConveyancePreference {
    fn default() -> Self {
        Self::None
    }
}