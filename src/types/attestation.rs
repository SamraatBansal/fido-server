//! Attestation (Registration) API types

use serde::{Deserialize, Serialize};
use super::common::*;
use super::{ServerResponse, AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs};

/// Request for attestation options (registration begin)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
}

/// Response for attestation options (registration begin)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<PublicKeyCredentialRpEntity>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<ServerPublicKeyCredentialUserEntity>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    
    #[serde(rename = "pubKeyCredParams", skip_serializing_if = "Option::is_none")]
    pub pub_key_cred_params: Option<Vec<PublicKeyCredentialParameters>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl ServerPublicKeyCredentialCreationOptionsResponse {
    /// Create a successful response with options
    pub fn ok_with_options(
        rp: PublicKeyCredentialRpEntity,
        user: ServerPublicKeyCredentialUserEntity,
        challenge: String,
        pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
        timeout: Option<u32>,
        exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        attestation: Option<AttestationConveyancePreference>,
        extensions: Option<AuthenticationExtensionsClientInputs>,
    ) -> Self {
        Self {
            base: ServerResponse::ok(),
            rp: Some(rp),
            user: Some(user),
            challenge: Some(challenge),
            pub_key_cred_params: Some(pub_key_cred_params),
            timeout,
            exclude_credentials,
            authenticator_selection,
            attestation,
            extensions,
        }
    }

    /// Create a failed response
    pub fn failed(error_message: impl Into<String>) -> Self {
        Self {
            base: ServerResponse::failed(error_message),
            rp: None,
            user: None,
            challenge: None,
            pub_key_cred_params: None,
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: None,
            extensions: None,
        }
    }
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Server public key credential for attestation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

/// Request for attestation result (registration finish)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResultRequest {
    #[serde(flatten)]
    pub credential: ServerPublicKeyCredential,
}

/// Response for attestation result (registration finish)
pub type AttestationResultResponse = ServerResponse;