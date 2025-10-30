//! Application setup and configuration

use actix_web::{web, App, HttpServer};
use std::sync::Arc;
use crate::config::Config;
use crate::controllers::{RegistrationController, AuthenticationController, HealthController};
use crate::services::{WebAuthnService, UserService, CredentialService, SecurityService};
use crate::db::{PgPool, create_pool, run_migrations, PgUserRepository, PgCredentialRepository, PgChallengeRepository};
use crate::middleware::{CorsMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware, RequestValidationMiddleware};

/// Application state
pub struct AppState {
    pub config: Config,
    pub db_pool: Option<Arc<PgPool>>,
    pub webauthn_service: Arc<WebAuthnService>,
    pub user_service: Arc<UserService>,
    pub credential_service: Arc<CredentialService>,
    pub security_service: Arc<SecurityService>,
}

impl AppState {
    /// Create new application state
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize database if configured
        let (db_pool, webauthn_service, user_service, credential_service, security_service) = 
            if !config.database.url.is_empty() {
                let pool = Arc::new(create_pool(&config.database.url)?);
                
                // Run migrations
                run_migrations(&pool)?;
                
                // Create repositories
                let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
                let credential_repo = Arc::new(PgCredentialRepository::new(pool.clone()));
                let challenge_repo = Arc::new(PgChallengeRepository::new(pool.clone()));
                
                // Create services
                let webauthn_service = Arc::new(WebAuthnService::new(
                    config.webauthn.clone(),
                    user_repo.clone(),
                    credential_repo.clone(),
                    challenge_repo.clone(),
                )?);
                
                let user_service = Arc::new(UserService::new(user_repo));
                let credential_service = Arc::new(CredentialService::new(credential_repo));
                let security_service = Arc::new(SecurityService::new(challenge_repo));
                
                (Some(pool), webauthn_service, user_service, credential_service, security_service)
            } else {
                // Use mock repositories for testing
                #[cfg(test)]
                {
                    use crate::db::repositories::mocks::{MockUserRepository, MockCredentialRepository, MockChallengeRepository};
                
                let user_repo = Arc::new(MockUserRepository::new());
                    let credential_repo = Arc::new(MockCredentialRepository::new());
                    let challenge_repo = Arc::new(MockChallengeRepository::new());
                    
                    let webauthn_service = Arc::new(WebAuthnService::new(
                        config.webauthn.clone(),
                        user_repo.clone(),
                        credential_repo.clone(),
                        challenge_repo.clone(),
                    )?);
                    
                    let user_service = Arc::new(UserService::new(user_repo));
                    let credential_service = Arc::new(CredentialService::new(credential_repo));
                    let security_service = Arc::new(SecurityService::new(challenge_repo));
                    
                    (None, webauthn_service, user_service, credential_service, security_service)
                }
                #[cfg(not(test))]
                {
                    return Err("Database configuration required for production".into());
                }
            };

        Ok(Self {
            config,
            db_pool,
            webauthn_service,
            user_service,
            credential_service,
            security_service,
        })
    }
}

/// Create HTTP server with application
pub async fn create_server(state: Arc<AppState>) -> Result<actix_web::dev::Server, Box<dyn std::error::Error>> {
    let host = state.config.server.host.clone();
    let port = state.config.server.port;
    let workers = state.config.server.workers.unwrap_or_else(|| num_cpus::get());

    // Create controllers
    let registration_controller = Arc::new(RegistrationController::new(state.webauthn_service.clone()));
    let authentication_controller = Arc::new(AuthenticationController::new(state.webauthn_service.clone()));
    let health_controller = Arc::new(HealthController::new(state.db_pool.clone()));

    let server = HttpServer::new(move || {
        // Configure CORS
        let cors = CorsMiddleware::configure(&state.config.security);

        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(cors)
            .wrap(RateLimitMiddleware::new(state.config.security.rate_limit_requests_per_minute))
            .wrap(SecurityHeadersMiddleware)
            .wrap(RequestValidationMiddleware)
            .configure(|cfg| {
                crate::routes::api::configure(
                    cfg,
                    registration_controller.clone(),
                    authentication_controller.clone(),
                    health_controller.clone(),
                );
            })
    })
    .bind((host, port))?
    .workers(workers);

    Ok(server.run())
}