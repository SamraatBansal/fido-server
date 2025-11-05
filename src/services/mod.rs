//! Service factory for creating WebAuthn services with different backends

use crate::config::Settings;
use crate::webauthn::{WebAuthnService, WebAuthnConfig, WebAuthnServiceImpl};
use crate::webauthn::memory_store::{InMemoryChallengeStore, InMemoryUserRepository, InMemoryCredentialRepository};
use crate::db::{PostgresChallengeStore, PostgresUserRepository, PostgresCredentialRepository, DbPool};
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
            require_user_verification: false,
            supported_algorithms: vec![-7, -257], // ES256, RS256
        };

        // Use in-memory service for development/testing
        let challenge_store = InMemoryChallengeStore::new();
        let user_repo = InMemoryUserRepository::new();
        let credential_repo = InMemoryCredentialRepository::new();
        
        let service = WebAuthnServiceImpl::new(
            webauthn_config,
            challenge_store,
            user_repo,
            credential_repo,
        )?;
        Ok(Arc::new(service))
    }
}