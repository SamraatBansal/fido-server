//! FIDO Server Main Entry Point

use actix_web::{App, HttpServer, middleware, web};
use fido_server::{
    config::settings::Settings,
    controllers::health_check,
    routes::{configure_api_routes, configure_health_routes},
    middleware::{configure_cors, security_headers},
    db::create_pool,
    services::{WebAuthnService, ChallengeService, CredentialService, UserService},
    config::WebAuthnConfig,
};
use std::env;
use std::sync::Mutex;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let settings = Settings::new()
        .expect("Failed to load configuration");

    // Create database connection pool
    let db_pool = create_pool()
        .expect("Failed to create database pool");

    // Initialize services
    let user_service = UserService::new();
    let credential_service = CredentialService::new();
    let challenge_service = ChallengeService::new();
    
    // Create WebAuthn configuration
    let webauthn_config = WebAuthnConfig::from(settings.webauthn);
    
    // Create WebAuthn service
    let webauthn_service = WebAuthnService::new(
        webauthn_config,
        challenge_service,
        credential_service,
        user_service,
    ).expect("Failed to create WebAuthn service");

    // Wrap services in Mutex for thread safety
    let webauthn_service = web::Data::new(Mutex::new(webauthn_service));

    // Get server configuration
    let host = env::var("HOST").unwrap_or_else(|_| settings.server.host);
    let port = env::var("PORT")
        .unwrap_or_else(|_| settings.server.port.to_string())
        .parse()
        .unwrap_or(settings.server.port);

    log::info!("Server will run at http://{}:{}", host, port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Add database pool to app state
            .app_data(db_pool.clone())
            .app_data(webauthn_service.clone())
            // Add middleware
            .wrap(middleware::Logger::default())
            .wrap(security_headers())
            .wrap(configure_cors())
            // Configure routes
            .service(configure_health_routes())
            .service(configure_api_routes())
            // Legacy health endpoints for backward compatibility
            .route("/health", web::get().to(health_check))
            .route("/api/v1/health", web::get().to(health_check))
    })
    .bind((host.as_str(), port))?
    .workers(num_cpus::get())
    .run()
    .await
}