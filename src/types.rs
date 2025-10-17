//! WebAuthn request and response types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response with status and error message
#[derive(Debug, Serialize, Deserialize)]
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

/// Request for attestation options
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

/// Response for attestation options
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: String,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Request for assertion options
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub user_verification: Option<String>,
}

/// Response for assertion options
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: u32,
    pub rp_id: String,
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: String,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Server public key credential
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

/// Server authenticator response (enum for attestation and assertion)
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "responseType")]
pub enum ServerAuthenticatorResponse {
    #[serde(rename = "attestation")]
    Attestation(ServerAuthenticatorAttestationResponse),
    #[serde(rename = "assertion")]
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Server authenticator attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Server authenticator assertion response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// RP entity
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

/// User entity for server response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub alg_type: String,
    pub alg: i32,
}

/// Public key credential descriptor
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

// For handling the actual ServerPublicKeyCredential with response field
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialWithResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub response: serde_json::Value,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

// Helper to determine response type
impl ServerPublicKeyCredentialWithResponse {
    pub fn parse_response(&self) -> Result<ServerAuthenticatorResponse, serde_json::Error> {
        // Check if it's an attestation response (has attestationObject)
        if self.response.get("attestationObject").is_some() {
            let attestation: ServerAuthenticatorAttestationResponse = 
                serde_json::from_value(self.response.clone())?;
            Ok(ServerAuthenticatorResponse::Attestation(attestation))
        } else if self.response.get("authenticatorData").is_some() {
            let assertion: ServerAuthenticatorAssertionResponse = 
                serde_json::from_value(self.response.clone())?;
            Ok(ServerAuthenticatorResponse::Assertion(assertion))
        } else {
            // Default to assertion for compatibility
            let assertion: ServerAuthenticatorAssertionResponse = 
                serde_json::from_value(self.response.clone())?;
            Ok(ServerAuthenticatorResponse::Assertion(assertion))
        }
    }
}