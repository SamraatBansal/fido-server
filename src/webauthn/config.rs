use std::sync::Arc;
use webauthn_rs::prelude::*;
use crate::error::AppError;

pub type WebAuthnInstance = WebAuthn<Arc<WebAuthnConfig>>;

#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
}

impl WebAuthnConfig {
    pub fn new(rp_name: String, rp_id: String, rp_origin: String) -> Self {
        Self {
            rp_name,
            rp_id,
            rp_origin,
        }
    }

    pub fn build_webauthn(&self) -> Result<WebAuthnInstance, AppError> {
        let rp = RelyingParty {
            id: self.rp_id.clone(),
            name: self.rp_name.clone(),
            origin: Url::parse(&self.rp_origin)
                .map_err(|e| AppError::WebAuthn(format!("Invalid origin URL: {}", e)))?,
        };

        let config = WebAuthnBuilder::new(rp)
            .map_err(|e| AppError::WebAuthn(format!("Failed to build WebAuthn: {}", e)))?
            .build();

        Ok(config)
    }
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self::new(
            "FIDO2 Server".to_string(),
            "localhost".to_string(),
            "https://localhost:8080".to_string(),
        )
    }
}