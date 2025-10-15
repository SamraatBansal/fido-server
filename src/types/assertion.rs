//! Assertion (Authentication) API types

use serde::{Deserialize, Serialize};
use super::common::*;
use super::{ServerResponse, AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs};

/// Request for assertion options (authentication begin)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

/// Response for assertion options (authentication begin)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl ServerPublicKeyCredentialGetOptionsResponse {
    /// Create a successful response with options
    pub fn ok_with_options(
        challenge: String,
        timeout: Option<u32>,
        rp_id: String,
        allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
        user_verification: Option<UserVerificationRequirement>,
        extensions: Option<AuthenticationExtensionsClientInputs>,
    ) -> Self {
        Self {
            base: ServerResponse::ok(),
            challenge: Some(challenge),
            timeout,
            rp_id: Some(rp_id),
            allow_credentials: Some(allow_credentials),
            user_verification,
            extensions,
        }
    }

    /// Create a failed response
    pub fn failed(error_message: impl Into<String>) -> Self {
        Self {
            base: ServerResponse::failed(error_message),
            challenge: None,
            timeout: None,
            rp_id: None,
            allow_credentials: None,
            user_verification: None,
            extensions: None,
        }
    }
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// Server public key credential for assertion
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialAssertion {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

/// Request for assertion result (authentication finish)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionResultRequest {
    #[serde(flatten)]
    pub credential: ServerPublicKeyCredentialAssertion,
}

/// Response for assertion result (authentication finish)
pub type AssertionResultResponse = ServerResponse;