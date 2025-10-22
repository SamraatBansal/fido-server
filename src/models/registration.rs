//! Registration-related models for FIDO2/WebAuthn

use serde::{Deserialize, Serialize};
use super::{
    AuthenticatorSelectionCriteria, AttestationConveyancePreference, PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, ServerPublicKeyCredential, ServerPublicKeyCredentialUserEntity,
    ServerResponse, ServerPublicKeyCredentialDescriptor,
};

/// Request for registration challenge options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

/// Response for registration challenge options
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
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<serde_json::Value>,
}

impl ServerPublicKeyCredentialCreationOptionsResponse {
    pub fn success(
        rp: PublicKeyCredentialRpEntity,
        user: ServerPublicKeyCredentialUserEntity,
        challenge: String,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp,
            user,
            challenge,
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            }],
            timeout: Some(60000),
            exclude_credentials: Some(vec![]),
            authenticator_selection: Some(AuthenticatorSelectionCriteria::default()),
            attestation: Some(AttestationConveyancePreference::None),
            extensions: None,
        }
    }
}

/// Server authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Registration completion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationCompletionRequest {
    pub id: String,
    #[serde(rename = "response")]
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Registration completion response
pub type RegistrationCompletionResponse = ServerResponse;