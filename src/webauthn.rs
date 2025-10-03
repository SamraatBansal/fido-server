//! WebAuthn core types and configuration

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{
    AuthenticatorSelectionCriteria, PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty,
};

/// WebAuthn configuration wrapper
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub inner: Webauthn,
}

impl WebAuthnConfig {
    /// Create a new WebAuthn configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    pub fn new(rp_id: &str, rp_name: &str, origin: &str) -> Result<Self, WebauthnError> {
        let rp_origin = Url::parse(origin).map_err(|_| WebauthnError::Configuration)?;

        let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
        builder = builder.rp_name(rp_name);
        let webauthn = builder.build()?;

        Ok(Self { inner: webauthn })
    }
}

/// User identifier for WebAuthn operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

// UserId conversion removed as it's not available in current webauthn-rs version

/// Registration challenge response
#[derive(Debug, Serialize)]
pub struct RegistrationChallenge {
    pub challenge: String,
    pub user: WebAuthnUser,
    pub rp: RelyingParty,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub timeout: u32,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
}

/// Authentication challenge response
#[derive(Debug, Serialize)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub timeout: u32,
    pub user_verification: String,
}

/// Registration request data
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub user: WebAuthnUser,
    pub attestation_response: String,
}

/// Authentication request data
#[derive(Debug, Deserialize)]
pub struct AuthenticationRequest {
    pub credential_id: String,
    pub authenticator_response: String,
}

/// User mapping data
#[derive(Debug, Serialize, Deserialize)]
pub struct UserMapping {
    pub id: Uuid,
    pub external_id: String,
    pub credential_id: String,
    pub user_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Create mapping request
#[derive(Debug, Deserialize)]
pub struct CreateMappingRequest {
    pub external_id: String,
    pub credential_id: String,
    pub user_id: Uuid,
}

/// Helper functions for WebAuthn operations
pub mod helpers {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rand::RngCore;

    /// Convert credential ID to base64url string
    #[must_use]
    pub fn credential_id_to_string(cred_id: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(cred_id)
    }

    /// Convert base64url string to credential ID
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid base64url
    pub fn string_to_credential_id(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s)
    }

    /// Generate a secure random challenge
    #[must_use]
    pub fn generate_challenge() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }
}
