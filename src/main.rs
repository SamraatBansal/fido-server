//! FIDO Server Main Entry Point

use actix_web::middleware::Logger;
use std::io;
use std::sync::Arc;
use fido_server::{Config, AppState, create_server};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    
    log::info!("Configuration loaded successfully");
    log::info!("Server will bind to {}:{}", config.server.host, config.server.port);
    log::info!("WebAuthn RP ID: {}", config.webauthn.rp_id);
    log::info!("WebAuthn RP Origin: {}", config.webauthn.rp_origin);

    // Create application state
    let state = Arc::new(AppState::new(config).await.expect("Failed to create application state"));

    // Create and run server
    let server = create_server(state).await.expect("Failed to create server");

    log::info!("FIDO Server started successfully");

    // Run the server
    server.await
}
