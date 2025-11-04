//! Service factory for creating WebAuthn services with different backends

use crate::config::Settings;
use crate::webauthn::{WebAuthnService, WebAuthnConfig, WebAuthnServiceImpl};
use std::sync::Arc;

/// Service factory for creating WebAuthn services
pub struct ServiceFactory;

impl ServiceFactory {
    /// Create a WebAuthn service based on configuration
    pub async fn create_webauthn_service(settings: &Settings) -> Result<Arc<dyn WebAuthnService>, Box<dyn std::error::Error>> {
        let webauthn_config = WebAuthnConfig {
            rp_name: settings.webauthn.rp_name.clone(),
            rp_id: settings.webauthn.rp_id.clone(),
            rp_origin: settings.webauthn.origin.clone(),
            timeout: 60000,
        };

        // Use in-memory service for development/testing
        let service = WebAuthnServiceImpl::new(webauthn_config);
        Ok(Arc::new(service))
    }
}