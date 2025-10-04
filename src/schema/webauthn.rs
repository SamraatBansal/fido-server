//! WebAuthn-specific schemas

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationState {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub challenge: String,
    pub registration_state: RegistrationState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationState {
    pub user_id: String,
    pub challenge: String,
    pub authentication_state: AuthenticationState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialCreationOptions {
    pub challenge: String,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRequestOptions {
    pub challenge: String,
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub user_verification: Option<UserVerificationPolicy>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}