//! Attestation (Registration) schema types

use serde::{Deserialize, Serialize};
use validator::Validate;
use super::{AuthenticatorSelectionCriteria, AuthenticationExtensionsClientOutputs, ServerResponse};

/// Request for registration options
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    #[validate(length(min = 1, max = 255, message = "Username is required and must be 1-255 characters"))]
    pub username: String,
    
    #[validate(length(min = 1, max = 255, message = "Display name is required and must be 1-255 characters"))]
    pub display_name: String,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Response for registration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: super::PublicKeyCredentialRpEntity,
    pub user: super::ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<super::PublicKeyCredentialParameters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<super::ServerPublicKeyCredentialDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<super::AuthenticationExtensionsClientInputs>,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerAuthenticatorAttestationResponse {
    #[validate(length(min = 1, message = "clientDataJSON is required"))]
    pub client_data_json: String,
    
    #[validate(length(min = 1, message = "attestationObject is required"))]
    pub attestation_object: String,
}

/// Server public key credential for attestation
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialAttestation {
    #[validate(length(min = 1, message = "Credential ID is required"))]
    pub id: String,
    
    #[validate(length(min = 1, message = "Raw ID is required"))]
    pub raw_id: String,
    
    #[validate(nested)]
    pub response: ServerAuthenticatorAttestationResponse,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
    
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Response for attestation result
pub type AttestationResultResponse = ServerResponse;