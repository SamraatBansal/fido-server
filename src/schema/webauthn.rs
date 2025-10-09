//! WebAuthn-specific request/response schemas

use serde::{Deserialize, Serialize};

/// WebAuthn credential creation options
#[derive(Debug, Serialize)]
pub struct CredentialCreationOptions {
    pub rp: RelyingParty,
    pub user: User,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u64,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
}

/// WebAuthn credential request options
#[derive(Debug, Serialize)]
pub struct CredentialRequestOptions {
    pub challenge: String,
    pub allow_credentials: Vec<AllowCredentials>,
    pub user_verification: String,
    pub timeout: u64,
}

/// Relying party information
#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

/// User information for WebAuthn
#[derive(Debug, Serialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<String>,
    pub user_verification: String,
    pub require_resident_key: bool,
}

/// Allow credentials for authentication
#[derive(Debug, Serialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Vec<String>,
}

/// Attestation response from client
#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AttestationResponseData,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Attestation response data
#[derive(Debug, Deserialize)]
pub struct AttestationResponseData {
    pub attestation_object: String,
    pub client_data_json: String,
}

/// Assertion response from client
#[derive(Debug, Deserialize)]
pub struct AssertionResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AssertionResponseData,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Assertion response data
#[derive(Debug, Deserialize)]
pub struct AssertionResponseData {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}