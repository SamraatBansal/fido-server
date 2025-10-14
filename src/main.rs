//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;
use std::sync::Arc;
use webauthn_rp_server::services::fido::FidoService;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // TODO: Load configuration from config file
    let host = "127.0.0.1";
    let port = 8080;

    // Initialize FIDO service
    let fido_service = Arc::new(
        FidoService::new()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to initialize FIDO service: {}", e)))?
    );

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(fido_service.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(webauthn_rp_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
