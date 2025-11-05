use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default)]
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(default)]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
    pub client_data_json: String,
}