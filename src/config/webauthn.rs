//! WebAuthn configuration module

use webauthn_rs::prelude::*;
use webauthn_rs_proto::*;
use url::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::error::{AppError, Result};

/// WebAuthn configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party name
    pub rp_name: String,
    /// Relying party ID
    pub rp_id: String,
    /// Relying party origin URL
    pub rp_origin: String,
    /// Challenge timeout duration
    pub challenge_timeout: Duration,
    /// Attestation preference
    pub attestation_preference: AttestationConveyancePreference,
    /// User verification policy
    pub user_verification_policy: UserVerificationPolicy,
    /// Authenticator selection criteria
    pub authenticator_selection: AuthenticatorSelectionCriteria,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "https://localhost:8080".to_string(),
            challenge_timeout: Duration::from_secs(300), // 5 minutes
            attestation_preference: AttestationConveyancePreference::Direct,
            user_verification_policy: UserVerificationPolicy::Preferred,
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                require_resident_key: false,
                user_verification: UserVerificationPolicy::Preferred,
            },
        }
    }
}

impl WebAuthnConfig {
    /// Convert to webauthn-rs Webauthn instance
    pub fn to_webauthn(&self) -> Result<Webauthn> {
        let rp = RelyingParty {
            name: self.rp_name.clone(),
            id: self.rp_id.clone(),
            origin: Url::parse(&self.rp_origin)
                .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {}", e)))?,
        };

        let config = WebauthnConfig {
            rp,
            challenge_timeout: self.challenge_timeout,
            ..Default::default()
        };

        Webauthn::new(config)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to create WebAuthn instance: {}", e)))
    }

    /// Validate that an origin matches the configured origin
    pub fn validate_origin(&self, origin: &str) -> Result<()> {
        let origin_url = Url::parse(origin)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {}", e)))?;
        
        let config_url = Url::parse(&self.rp_origin)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid config origin URL: {}", e)))?;

        if origin_url.origin() != config_url.origin() {
            return Err(AppError::WebAuthnError("Origin mismatch".to_string()));
        }

        Ok(())
    }
}

impl From<crate::config::settings::WebAuthnSettings> for WebAuthnConfig {
    fn from(settings: crate::config::settings::WebAuthnSettings) -> Self {
        Self {
            rp_name: settings.rp_name,
            rp_id: settings.rp_id,
            rp_origin: settings.origin,
            ..Default::default()
        }
    }
}