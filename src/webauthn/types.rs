//! WebAuthn data structures and types
//! 
//! This module contains all the data structures needed for FIDO2/WebAuthn implementation
//! following the specification provided.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
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

/// Registration: ServerPublicKeyCredentialCreationOptionsRequest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// AuthenticatorSelectionCriteria from WebAuthn spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Registration: ServerPublicKeyCredentialCreationOptionsResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// PublicKeyCredentialRpEntity from WebAuthn spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// ServerPublicKeyCredentialUserEntity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// PublicKeyCredentialParameters from WebAuthn spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

/// ServerPublicKeyCredentialDescriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

/// AuthenticationExtensionsClientInputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Registration: ServerPublicKeyCredential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
}

/// ServerAuthenticatorAttestationResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Authentication: ServerPublicKeyCredentialGetOptionsRequest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

/// Authentication: ServerPublicKeyCredentialGetOptionsResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub rp_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication: ServerAuthenticatorAssertionResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
    pub client_data_json: String,
}

/// Authentication assertion credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAssertionPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
}

/// Convert ServerPublicKeyCredential to assertion version
impl From<ServerPublicKeyCredential> for ServerAssertionPublicKeyCredential {
    fn from(cred: ServerPublicKeyCredential) -> Self {
        // This is a simplified conversion - in practice, you'd need to handle
        // the different response types properly
        Self {
            id: cred.id,
            cred_type: cred.cred_type,
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: String::new(),
                signature: String::new(),
                user_handle: String::new(),
                client_data_json: String::new(),
            },
            get_client_extension_results: cred.get_client_extension_results,
        }
    }
}

/// WebAuthn configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u64,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "Example Corporation".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
            timeout: 60000,
        }
    }
}

/// Challenge data for storing challenges
#[derive(Debug, Clone)]
pub struct ChallengeData {
    pub challenge: String,
    pub username: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub challenge_type: ChallengeType,
}

#[derive(Debug, Clone)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

/// User data structure
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Credential data structure
#[derive(Debug, Clone)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}