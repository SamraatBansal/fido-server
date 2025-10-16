//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, App, HttpServer, web::Data};
use std::io;
use std::sync::Arc;
use fido_server::services::{WebAuthnService, WebAuthnConfig};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // TODO: Load configuration from config file
    let host = "127.0.0.1";
    let port = 8080;

    // Initialize WebAuthn service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(
        WebAuthnService::new(webauthn_config)
            .expect("Failed to initialize WebAuthn service")
    );

    // TODO: Initialize database connection pool

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(Data::new(Arc::clone(&webauthn_service)))
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
