//! Registration DTO types

use serde::{Deserialize, Serialize};
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria,
};
use super::common::*;

/// Public key credential parameters
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

/// Relying party entity
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyCredentialRpEntity {
    pub id: Option<String>,
    pub name: String,
}

/// Server public key credential creation options request
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default)]
    pub attestation: AttestationConveyancePreference,
}

/// Server public key credential creation options response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub server_response: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String, // base64url encoded
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", default)]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default)]
    pub attestation: AttestationConveyancePreference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Registration result request (from client)
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationResultRequest {
    #[serde(flatten)]
    pub credential: ServerPublicKeyCredential,
}

/// Registration result response (to client)
pub type RegistrationResultResponse = ServerResponse;