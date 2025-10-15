//! Common types used across FIDO2 API endpoints

use serde::{Deserialize, Serialize};

/// Authenticator attachment preference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

/// User verification requirement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

/// Resident key requirement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,
    
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i32,
}

/// Relying party entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// User entity for server responses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Credential descriptor for server responses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authenticator transport
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
    Hybrid,
}