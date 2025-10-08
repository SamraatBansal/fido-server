//! WebAuthn FIDO2 conformance API schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{
    AuthenticatorSelectionCriteria, AttestationConveyancePreference,
    AuthenticationExtensionsClientInputs, PublicKeyCredentialRpEntity,
    PublicKeyCredentialParameters, PublicKeyCredentialDescriptor,
    UserVerificationRequirement, AuthenticatorTransport,
};

/// Registration options request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegistrationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Registration options response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u64,
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Server public key credential user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Authentication options request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    pub user_verification: Option<UserVerificationRequirement>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication options response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: u64,
    pub rp_id: String,
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: UserVerificationRequirement,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Server public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Vec<AuthenticatorTransport>,
}

/// Server response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

/// Re-export webauthn-rs types
pub use webauthn_rs::prelude::*;