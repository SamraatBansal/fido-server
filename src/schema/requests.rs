use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AttestationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,

    #[validate(length(min = 1, max = 255))]
    pub display_name: String,

    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<RegistrationExtensionInputs>,
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub require_resident_key: Option<bool>,
    pub resident_key: Option<ResidentKeyRequirement>,
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UserVerificationPolicy {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationExtensionInputs {
    pub cred_props: Option<bool>,
    pub large_blob: Option<LargeBlobExtensionInput>,
    pub extensions: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeBlobExtensionInput {
    pub support: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<RegistrationExtensionOutputs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    pub type_: String,
    pub alg: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationExtensionOutputs {
    pub cred_props: Option<CredentialPropertiesOutput>,
    pub large_blob: Option<LargeBlobExtensionOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPropertiesOutput {
    pub rk: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeBlobExtensionOutput {
    pub supported: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AttestationResultRequest {
    #[validate(length(min = 1))]
    pub session_id: String,

    #[validate(length(min = 1))]
    pub credential_id: String,

    #[validate(length(min = 1))]
    pub raw_id: String,

    pub response: AuthenticatorAttestationResponse,
    pub client_extension_results: Option<RegistrationExtensionOutputs>,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultResponse {
    pub status: String,
    pub error_message: String,
    pub credential_id: String,
    pub aaguid: Option<String>,
    pub sign_count: u32,
    pub user_verified: bool,
    pub new_identity: Option<PublicKeyCredentialUserEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AssertionOptionsRequest {
    pub username: Option<String>,
    pub user_verification: Option<UserVerificationPolicy>,
    pub extensions: Option<AuthenticationExtensionInputs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionInputs {
    pub large_blob: Option<LargeBlobAuthenticationInput>,
    pub extensions: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeBlobAuthenticationInput {
    pub read: Option<bool>,
    pub write: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: u32,
    pub rp_id: String,
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub user_verification: Option<UserVerificationPolicy>,
    pub extensions: Option<AuthenticationExtensionOutputs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionOutputs {
    pub large_blob: Option<LargeBlobAuthenticationOutput>,
    pub extensions: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeBlobAuthenticationOutput {
    pub supported: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AssertionResultRequest {
    #[validate(length(min = 1))]
    pub session_id: String,

    #[validate(length(min = 1))]
    pub credential_id: String,

    #[validate(length(min = 1))]
    pub raw_id: String,

    pub response: AuthenticatorAssertionResponse,
    pub client_extension_results: Option<AuthenticationExtensionOutputs>,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResultResponse {
    pub status: String,
    pub error_message: String,
    pub credential_id: String,
    pub sign_count: u32,
    pub user_verified: bool,
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialListResponse {
    pub status: String,
    pub error_message: String,
    pub credentials: Vec<CredentialInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub credential_id: String,
    pub type_: String,
    pub name: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
}
