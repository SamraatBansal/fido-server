//! Request models for FIDO2/WebAuthn endpoints

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request for attestation options (credential creation)
#[derive(Debug, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    
    #[validate(length(min = 1, max = 255))]
    #[serde(rename = "displayName")]
    pub display_name: String,
    
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Request for assertion options (credential get)
#[derive(Debug, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    
    #[serde(default = "default_user_verification", rename = "userVerification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

/// Authenticator selection criteria
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(default, rename = "requireResidentKey")]
    pub require_resident_key: bool,
    
    #[serde(default, rename = "authenticatorAttachment")]
    pub authenticator_attachment: String,
    
    #[serde(default = "default_user_verification", rename = "userVerification")]
    pub user_verification: String,
}

/// Server public key credential for attestation and assertion results
#[derive(Debug, Deserialize, Validate)]
pub struct ServerPublicKeyCredential {
    #[validate(length(min = 1))]
    pub id: String,
    
    #[validate(length(min = 1))]
    #[serde(rename = "type")]
    pub credential_type: String,
    
    pub response: ServerAuthenticatorResponse,
    
    #[serde(default, rename = "getClientExtensionResults")]
    pub get_client_extension_results: serde_json::Value,
}

/// Server authenticator response (base for both attestation and assertion)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Server authenticator attestation response
#[derive(Debug, Deserialize, Validate)]
pub struct ServerAuthenticatorAttestationResponse {
    #[validate(length(min = 1))]
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    
    #[validate(length(min = 1))]
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Server authenticator assertion response
#[derive(Debug, Deserialize, Validate)]
pub struct ServerAuthenticatorAssertionResponse {
    #[validate(length(min = 1), rename = "clientDataJSON")]
    pub client_data_json: String,
    
    #[validate(length(min = 1), rename = "authenticatorData")]
    pub authenticator_data: String,
    
    #[validate(length(min = 1))]
    pub signature: String,
    
    #[serde(default, rename = "userHandle")]
    pub user_handle: String,
}