use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::env;
use fido2_webauthn_server::memory_service::MemoryWebAuthnService;
use fido2_webauthn_server::memory_handlers::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize WebAuthn service with memory storage
    let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_name = env::var("RP_NAME").unwrap_or_else(|_| "FIDO2 WebAuthn Server".to_string());
    let rp_origin = env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let webauthn_service = match MemoryWebAuthnService::new(&rp_id, &rp_name, &rp_origin) {
        Ok(service) => service,
        Err(e) => {
            log::error!("Failed to initialize WebAuthn service: {}", e);
            std::process::exit(1);
        }
    };

    let bind_address = env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    
    log::info!("Starting FIDO2 WebAuthn server on {}", bind_address);
    log::info!("RP ID: {}", rp_id);
    log::info!("RP Origin: {}", rp_origin);
    log::info!("Using in-memory storage for testing");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .app_data(web::Data::new(webauthn_service.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(start_registration))
                    .route("/result", web::post().to(finish_registration)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(start_authentication))
                    .route("/result", web::post().to(finish_authentication)),
            )
            .route("/health", web::get().to(health_check))
    })
    .bind(&bind_address)?
    .run()
    .await
}