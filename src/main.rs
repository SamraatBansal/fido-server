//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{
    middleware::{DefaultHeaders, Logger, NormalizePath}, 
    web, App, HttpServer, Result
};
use fido_server::{
    config::Settings,
    state::AppState,
    error::AppError,
};
use std::io;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let config = Settings::new().map_err(|e| {
        log::error!("Failed to load configuration: {}", e);
        io::Error::new(io::ErrorKind::InvalidData, format!("Configuration error: {}", e))
    })?;

    let host = config.server.host.clone();
    let port = config.server.port;

    // Initialize application state with connection pools
    log::info!("Initializing application state...");
    let app_state = AppState::new(config).await.map_err(|e| {
        log::error!("Failed to initialize application state: {}", e);
        io::Error::new(io::ErrorKind::ConnectionRefused, format!("State initialization error: {}", e))
    })?;

    log::info!("Server starting at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS for FIDO2/WebAuthn requirements
        let cors = Cors::default()
            .allow_any_origin() // TODO: Configure specific origins for production
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            // Add application state
            .app_data(web::Data::new(app_state.clone()))
            // Add middleware
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(NormalizePath::trim())
            .wrap(DefaultHeaders::new()
                .add(("X-Content-Type-Options", "nosniff"))
                .add(("X-Frame-Options", "DENY"))
                .add(("X-XSS-Protection", "1; mode=block"))
                .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains")))
            // Configure routes
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
