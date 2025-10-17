//! WebAuthn data types for FIDO2 conformance

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub errorMessage: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            errorMessage: message.into(),
        }
    }
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub requireResidentKey: Option<bool>,
    pub authenticatorAttachment: Option<String>,
    pub userVerification: Option<String>,
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
        AttestationConveyancePreference::None
    }
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Public key credential user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub displayName: String,
}

/// Public key credential RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Request for credential creation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub displayName: String,
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default)]
    pub attestation: AttestationConveyancePreference,
}

/// Response for credential creation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    #[serde(default)]
    pub excludeCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Server authenticator response base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorResponse {
    #[serde(flatten)]
    pub client_data: serde_json::Value,
}

/// Server authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub clientDataJSON: String,
    pub attestationObject: String,
}

/// Server authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticatorData: String,
    pub signature: String,
    pub userHandle: Option<String>,
    pub clientDataJSON: String,
}

/// Server public key credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: serde_json::Value,
    #[serde(rename = "getClientExtensionResults")]
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Request for credential get options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub userVerification: Option<String>,
}

/// Response for credential get options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub challenge: String,
    pub timeout: Option<u64>,
    pub rpId: String,
    pub allowCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub userVerification: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}