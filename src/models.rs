//! WebAuthn data models

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Server response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorMessage: Option<String>,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            errorMessage: None,
        }
    }
    
    pub fn success_with_data<T: Serialize>(data: T) -> Result<serde_json::Value, serde_json::Error> {
        let mut response = serde_json::to_value(Self::success())?;
        if let serde_json::Value::Object(ref mut map) = response {
            let data_value = serde_json::to_value(data)?;
            if let serde_json::Value::Object(data_map) = data_value {
                for (key, value) in data_map {
                    map.insert(key, value);
                }
            }
        }
        Ok(response)
    }
    
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            errorMessage: Some(message.into()),
        }
    }
}

/// Registration challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub displayName: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Registration challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorMessage: Option<String>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub excludeCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

/// Authentication challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorMessage: Option<String>,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub rpId: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allowCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

/// Public key credential for registration/verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(skip_serializing_if = "AuthenticationExtensionsClientOutputs::is_empty", default)]
    pub getClientExtensionResults: AuthenticationExtensionsClientOutputs,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authenticator response (union type)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub clientDataJSON: String,
    pub attestationObject: String,
}

/// Assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticatorData: String,
    pub clientDataJSON: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userHandle: Option<String>,
}

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub displayName: String,
}

/// RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: String,
}

/// Credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub alg_type: String,
    pub alg: i32,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requireResidentKey: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorAttachment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userVerification: Option<String>,
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Authentication extensions client outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientOutputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

impl Default for AuthenticationExtensionsClientInputs {
    fn default() -> Self {
        Self {
            extensions: HashMap::new(),
        }
    }
}

impl Default for AuthenticationExtensionsClientOutputs {
    fn default() -> Self {
        Self {
            extensions: HashMap::new(),
        }
    }
}