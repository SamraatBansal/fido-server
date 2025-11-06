use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use fido2_webauthn_server::*;
use std::env;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    // Establish database connection
    let db_pool = Arc::new(match establish_connection_pool() {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to establish database connection: {}", e);
            std::process::exit(1);
        }
    });
    
    // Run migrations
    if let Err(e) = run_migrations(&db_pool) {
        tracing::error!("Failed to run migrations: {}", e);
        std::process::exit(1);
    }

    // Initialize WebAuthn service
    let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_name = env::var("RP_NAME").unwrap_or_else(|_| "FIDO2 WebAuthn Server".to_string());
    let rp_origin = env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let webauthn_service = match WebAuthnService::new(&rp_id, &rp_name, &rp_origin, db_pool.clone()) {
        Ok(service) => service,
        Err(e) => {
            tracing::error!("Failed to initialize WebAuthn service: {}", e);
            std::process::exit(1);
        }
    };

    let bind_address = env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    
    tracing::info!("Starting FIDO2 WebAuthn server on {}", bind_address);
    tracing::info!("RP ID: {}", rp_id);
    tracing::info!("RP Origin: {}", rp_origin);

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