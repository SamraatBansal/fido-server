//! Credential-related request/response schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs_proto::{
    AllowCredentials, AuthenticatorSelectionCriteria, PubKeyCredParams, RelyingParty,
};

/// Registration start request
#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
}

/// Registration start response
#[derive(Debug, Serialize)]
pub struct RegistrationStartResponse {
    pub challenge: String,
    pub user: crate::webauthn::WebAuthnUser,
    pub rp: RelyingParty,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub timeout: u32,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
}

/// Registration finish request
#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    pub user_id: Uuid,
    pub attestation_response: String,
}

/// Registration finish response
#[derive(Debug, Serialize)]
pub struct RegistrationFinishResponse {
    pub credential_id: String,
    pub user_id: Uuid,
}

/// Authentication start request
#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: Option<String>,
    pub credential_id: Option<String>,
}

/// Authentication start response
#[derive(Debug, Serialize)]
pub struct AuthenticationStartResponse {
    pub challenge: String,
    pub allow_credentials: Vec<AllowCredentials>,
    pub timeout: u32,
    pub user_verification: String,
}

/// Authentication finish request
#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub credential_id: String,
    pub authenticator_response: String,
}

/// Authentication finish response
#[derive(Debug, Serialize)]
pub struct AuthenticationFinishResponse {
    pub success: bool,
    pub user_id: Option<Uuid>,
    pub credential_id: String,
}
