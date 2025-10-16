//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;
use fido_server::services::{WebAuthnService, WebAuthnServiceImpl, WebAuthnConfig};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = WebAuthnServiceImpl::new(webauthn_config)
        .expect("Failed to initialize WebAuthn service");

    let host = "127.0.0.1";
    let port = 8080;

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
            .app_data(web::Data::new(webauthn_service.clone()))
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
