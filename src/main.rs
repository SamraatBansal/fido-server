//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, App, HttpServer};
use fido_server::{
    models::webauthn::WebAuthnConfig,
    routes::api::configure_fido_routes,
    services::{WebAuthnService, WebAuthnServiceImpl},
};
use std::io;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let webauthn_config = WebAuthnConfig::default();
    
    // Initialize WebAuthn service
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebAuthnServiceImpl::new(webauthn_config));

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
            .configure(|cfg| configure_fido_routes(cfg, webauthn_service.clone()))
    })
    .bind((host, port))?
    .run()
    .await
}
