use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use webauthn_rs_proto::{AuthenticatorSelectionCriteria, AttestationConveyancePreference, UserVerificationPolicy};

// Registration request schemas
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationBeginRequest {
    pub username: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: AttestationConveyancePreference,
}

fn default_attestation() -> AttestationConveyancePreference {
    AttestationConveyancePreference::None
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCompleteRequest {
    pub id: String, // base64url encoded credential ID
    #[serde(rename = "response")]
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String, // Should be "public-key"
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String, // base64url encoded
    pub attestation_object: String, // base64url encoded
}

// Authentication request schemas
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationBeginRequest {
    pub username: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: UserVerificationPolicy,
}

fn default_user_verification() -> UserVerificationPolicy {
    UserVerificationPolicy::Preferred
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationCompleteRequest {
    pub id: String, // base64url encoded credential ID
    #[serde(rename = "response")]
    pub response: AuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub client_extension_results: HashMap<String, serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String, // Should be "public-key"
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: String, // base64url encoded
    pub signature: String, // base64url encoded
    pub user_handle: String, // base64url encoded (can be empty)
    pub client_data_json: String, // base64url encoded
}