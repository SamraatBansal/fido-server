//! Main application entry point

use actix_web::{App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use std::sync::Arc;
use env_logger::Env;

use fido_server::{
    config::AppConfig,
    services::{MockWebAuthnService, WebAuthnService},
    routes::configure_routes,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // Load configuration
    let config = AppConfig::from_env().expect("Failed to load configuration");

    // Create WebAuthn service
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(MockWebAuthnService::new());

    // Configure CORS
    let cors = Cors::default()
        .allow_any_origin()
        .allow_any_method()
        .allow_any_header()
        .max_age(3600);

    // Create HTTP server
    let server = HttpServer::new(move || {
        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .service(configure_routes(Arc::clone(&webauthn_service)))
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?;

    log::info!("Starting FIDO2/WebAuthn server on {}:{}", config.server.host, config.server.port);

    server.run().await
}