//! Response models for FIDO2/WebAuthn endpoints

use serde::Serialize;
use serde_json::Value;

/// Base server response
#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "errorMessage")]
    pub error_message: Option<String>,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            errorMessage: None,
        }
    }
    
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: Some(message.into()),
        }
    }
}

/// Response for attestation options (credential creation)
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    
    #[serde(skip_serializing_if = "Option::is_none", rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// Response for assertion options (credential get)
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    
    pub challenge: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    
    #[serde(rename = "rpId")]
    pub rp_id: String,
    
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    
    #[serde(skip_serializing_if = "Option::is_none", rename = "userVerification")]
    pub user_verification: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// Relying Party entity
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// Server public key credential user entity
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i64,
}

/// Server public key credential descriptor
#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

/// Authenticator selection criteria (re-export from requests)
pub use crate::models::requests::AuthenticatorSelectionCriteria;