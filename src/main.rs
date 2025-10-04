//! FIDO Server Main Entry Point

use actix_web::{App, HttpServer, middleware};
use std::io;
use std::env;

use fido_server::{
    config::{Settings, WebAuthnConfig},
    db::DbManager,
    services::{WebAuthnService, SessionService},
    middleware::{security_headers, cors_config, request_id, logging::request_logger},
    routes::api::configure,
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let settings = Settings::new()
        .map_err(|e| {
            log::error!("Failed to load configuration: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "Configuration error")
        })?;

    // Initialize database connection pool
    let db_manager = DbManager::new(&settings.database.url, settings.database.max_pool_size)
        .map_err(|e| {
            log::error!("Failed to initialize database: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "Database initialization error")
        })?;

    log::info!("Database connection pool initialized");

    // Initialize WebAuthn configuration
    let webauthn_config = WebAuthnConfig::from(settings.webauthn.clone());
    
    // Initialize session service
    let jwt_secret = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-this-secret-in-production".to_string());
    let session_timeout_hours = env::var("SESSION_TIMEOUT_HOURS")
        .unwrap_or_else(|_| "24".to_string())
        .parse()
        .unwrap_or(24);
    
    let session_service = SessionService::new(jwt_secret, session_timeout_hours);

    // Initialize WebAuthn service
    let webauthn_service = WebAuthnService::new(webauthn_config, session_service)
        .map_err(|e| {
            log::error!("Failed to initialize WebAuthn service: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "WebAuthn service initialization error")
        })?;

    log::info!("WebAuthn service initialized");

    let host = settings.server.host.clone();
    let port = settings.server.port;

    log::info!("Server will run at http://{}:{}", host, port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Add data for dependency injection
            .app_data(web::Data::new(db_manager.clone()))
            .app_data(web::Data::new(webauthn_service.clone()))
            
            // Add middleware
            .wrap(middleware::Compress::default())
            .wrap(security_headers())
            .wrap(cors_config())
            .wrap(request_id())
            .wrap(request_logger())
            
            // Configure routes
            .configure(configure)
    })
    .bind((host.as_str(), port))?
    .workers(num_cpus::get())
    .run()
    .await
}
