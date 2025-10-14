use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u64,
    pub attestation_preference: AttestationConveyancePreference,
    pub user_verification: UserVerificationPolicy,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "https://localhost:8443".to_string(),
            timeout: 60000,
            attestation_preference: AttestationConveyancePreference::None,
            user_verification: UserVerificationPolicy::Preferred,
        }
    }
}

impl From<WebAuthnConfig> for WebAuthn<WebAuthnConfig> {
    fn from(config: WebAuthnConfig) -> Self {
        WebAuthn::new(
            config.rp_name.clone(),
            config.rp_id.clone(),
            config.rp_origin.clone(),
            config,
        )
    }
}