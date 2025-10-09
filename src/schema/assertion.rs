//! Assertion (Authentication) schema types

use serde::{Deserialize, Serialize};
use validator::Validate;
use super::{AuthenticationExtensionsClientOutputs, ServerResponse};

/// Request for assertion options
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    #[validate(length(min = 1, max = 255, message = "Username is required and must be 1-255 characters"))]
    pub username: String,
    
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

/// Response for assertion options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub rp_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<super::ServerPublicKeyCredentialDescriptor>,
    pub user_verification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<super::AuthenticationExtensionsClientInputs>,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerAuthenticatorAssertionResponse {
    #[validate(length(min = 1, message = "authenticatorData is required"))]
    pub authenticator_data: String,
    
    #[validate(length(min = 1, message = "clientDataJSON is required"))]
    pub client_data_json: String,
    
    #[validate(length(min = 1, message = "signature is required"))]
    pub signature: String,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// Server public key credential for assertion
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialAssertion {
    #[validate(length(min = 1, message = "Credential ID is required"))]
    pub id: String,
    
    #[validate(length(min = 1, message = "Raw ID is required"))]
    pub raw_id: String,
    
    #[validate(nested)]
    pub response: ServerAuthenticatorAssertionResponse,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
    
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Response for assertion result
pub type AssertionResultResponse = ServerResponse;