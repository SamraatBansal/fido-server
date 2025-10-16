//! Request and Response DTOs for FIDO2/WebAuthn conformance API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response with status and error message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub errorMessage: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            errorMessage: String::new(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            errorMessage: message.into(),
        }
    }
}

/// Registration challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub displayName: String,
    #[serde(rename = "authenticatorSelection", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Registration challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

/// Authentication challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowCredentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Registration verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationVerificationRequest {
    pub id: String,
    pub rawId: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults", default)]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authentication verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationVerificationRequest {
    pub id: String,
    pub rawId: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults", default)]
    pub get_client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle", default, skip_serializing_if = "String::is_empty")]
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Relying party entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i64,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey", default)]
    pub require_resident_key: bool,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
}

/// User verification requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

/// Authenticator attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorAttachment {
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// Authenticator transport
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    #[serde(rename = "internal")]
    Internal,
}

/// Public key credential type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublicKeyCredentialType {
    PublicKey,
}