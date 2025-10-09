//! Common schema types used across FIDO2/WebAuthn APIs

use serde::{Deserialize, Serialize};
use validator::Validate;

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
            error_message: String::new(),
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
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    
    #[serde(default)]
    pub require_resident_key: bool,
    
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// RP entity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: String,
}

/// User entity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Authentication extensions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
}

/// Authentication extensions outputs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticationExtensionsClientOutputs {
    #[serde(flatten, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
}