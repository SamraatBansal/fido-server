use crate::config::AppConfig;
use crate::db::repositories::{
    PgAuditLogRepository, PgAuthSessionRepository, PgCredentialRepository, PgUserRepository,
};
use crate::db::{establish_connection_pool, PgPool};
use crate::services::{CredentialService, UserService, WebAuthnService};
use std::sync::Arc;

pub struct AppState {
    pub webauthn_service: Arc<WebAuthnService>,
    pub user_service: Arc<UserService>,
    pub credential_service: Arc<CredentialService>,
    pub config: AppConfig,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize database connection pool
        let pool = establish_connection_pool()?;

        // Run migrations
        self::run_migrations(&pool)?;

        // Initialize repositories
        let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
        let credential_repo = Arc::new(PgCredentialRepository::new(pool.clone()));
        let session_repo = Arc::new(PgAuthSessionRepository::new(pool.clone()));
        let audit_repo = Arc::new(PgAuditLogRepository::new(pool.clone()));

        // Initialize services
        let webauthn_service = Arc::new(WebAuthnService::new(
            config.webauthn.clone(),
            user_repo.clone(),
            credential_repo.clone(),
            session_repo.clone(),
            audit_repo.clone(),
        )?);

        let user_service = Arc::new(UserService::new(
            user_repo.clone(),
            credential_repo.clone(),
            audit_repo.clone(),
        ));

        let credential_service = Arc::new(CredentialService::new(
            credential_repo.clone(),
            user_repo.clone(),
            audit_repo.clone(),
        ));

        Ok(Self {
            webauthn_service,
            user_service,
            credential_service,
            config,
        })
    }
}

fn run_migrations(_pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // Skip migrations for now - they would be run manually
    Ok(())
}
