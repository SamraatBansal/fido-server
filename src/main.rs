//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, App, HttpServer, web};
use std::sync::Arc;
use std::time::Duration;

use fido_server::{
    config::{AppConfig, DatabaseConfig, WebAuthnConfig},
    controllers::health,
    db::{create_pool, run_migrations},
    error::handle_404,
    middleware::{cors::default_cors, security::SecurityHeadersMiddleware, ClientIpMiddleware},
    routes::{api, health as health_routes},
    services::{
        CredentialService, FidoService, UserService, 
        SecureSessionManager, AttestationVerifier, JwtManager, AuditLogger
    },
    db::repositories::{DieselCredentialRepository, DieselSessionRepository, DieselUserRepository},
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let app_config = AppConfig::default();
    let db_config = DatabaseConfig::default();
    let webauthn_config = Arc::new(WebAuthnConfig::default());

    // Initialize database connection pool
    log::info!("Initializing database connection pool...");
    let db_pool = create_pool(&db_config).expect("Failed to create database pool");
    let db_pool_arc = Arc::new(db_pool);
    
    // Run database migrations
    log::info!("Running database migrations...");
    run_migrations(&db_pool_arc).expect("Failed to run migrations");

    // Initialize repositories
    let user_repo = Arc::new(DieselUserRepository::new(db_pool_arc.clone()));
    let credential_repo = Arc::new(DieselCredentialRepository::new(db_pool_arc.clone()));
    let session_repo = Arc::new(DieselSessionRepository::new(db_pool_arc.clone()));

    // Initialize security components
    let session_manager = Arc::new(SecureSessionManager::new(
        session_repo.clone(),
        Duration::from_secs(300), // 5 minutes
        5, // max sessions per user
    ));
    
    let attestation_verifier = Arc::new(AttestationVerifier::new());
    
    let jwt_secret = b"your-super-secret-jwt-key-change-in-production"; // In production, load from config
    let jwt_manager = Arc::new(JwtManager::new(jwt_secret).expect("Failed to create JWT manager"));
    
    let audit_logger = Arc::new(AuditLogger::new());

    // Initialize services
    let user_service = Arc::new(UserService::new(user_repo.clone()));
    let credential_service = Arc::new(CredentialService::new(credential_repo.clone()));
    
    let fido_service = Arc::new(FidoService::new(
        webauthn_config.clone(),
        user_repo.clone(),
        credential_repo.clone(),
        session_manager.clone(),
        attestation_verifier.clone(),
        jwt_manager.clone(),
        audit_logger.clone(),
    ));

    let host = app_config.server.host.clone();
    let port = app_config.server.port;

    log::info!("Server running at http://{}:{}", host, port);

    // Create HTTP server
    HttpServer::new(move || {
        // Configure CORS
        let cors = default_cors();

        App::new()
            // Add data for dependency injection
            .app_data(web::Data::new(fido_service.clone()))
            .app_data(web::Data::new(user_service.clone()))
            .app_data(web::Data::new(credential_service.clone()))
            .app_data(web::Data::new(webauthn_config.clone()))
            // Add middleware
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(SecurityHeadersMiddleware)
            // Configure routes
            .configure(health_routes::configure)
            .configure(api::configure)
            // Default handler for 404
            .default_service(web::route().to(handle_404))
    })
    .bind((host, port))?
    .run()
    .await
}