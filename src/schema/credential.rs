//! Credential schema types

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: super::PublicKeyCredentialRpEntity,
    pub user: super::ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub type_: String,
}

// Authentication schemas

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialAssertion {
    pub id: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub type_: String,
}