//! Service factory for creating WebAuthn services with different backends

use crate::config::Settings;
use crate::webauthn::{WebAuthnService, WebAuthnConfig, WebAuthnServiceImpl, ProductionWebAuthnService};
use crate::db::{Pool, PostgresUserRepository, PostgresCredentialRepository, PostgresChallengeRepository, establish_connection};
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

        if settings.database.in_memory {
            // Use in-memory service for development/testing
            let service = WebAuthnServiceImpl::new(webauthn_config);
            Ok(Arc::new(service))
        } else {
            // Use production database-backed service
            let pool = establish_connection(&settings.database.url)?;
            let pool = Arc::new(pool);

            // Create repositories
            let user_repo = Arc::new(PostgresUserRepository::new(pool.clone()));
            let credential_repo = Arc::new(PostgresCredentialRepository::new(pool.clone()));
            let challenge_repo = Arc::new(PostgresChallengeRepository::new(pool));

            // Create production service
            let service = ProductionWebAuthnService::new(
                webauthn_config,
                user_repo,
                credential_repo,
                challenge_repo,
            );
            
            Ok(Arc::new(service))
        }
    }

    /// Create database connection pool
    pub fn create_db_pool(database_url: &str, _max_pool_size: u32) -> Result<Pool, Box<dyn std::error::Error>> {
        let pool = establish_connection(database_url)?;
        Ok(Arc::new(pool))
    }
}