use serde::{Deserialize, Serialize};

/// Request for /attestation/options endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: AttestationConveyancePreference,
}

/// Request for /assertion/options endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

/// Request for /attestation/result endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResultRequest {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: AttestationResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub client_extension_results: Option<serde_json::Value>,
}

/// Request for /assertion/result endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionResultRequest {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: AssertionResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub client_extension_results: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

fn default_attestation() -> AttestationConveyancePreference {
    AttestationConveyancePreference::None
}