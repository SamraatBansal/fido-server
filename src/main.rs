//! Main application entry point

use actix_web::{App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use std::sync::Arc;
use env_logger::Env;

use fido_server::{
    config::AppConfig,
    db::establish_connection,
    services::{WebAuthnServiceImpl, PgUserRepository, PgCredentialRepository, PgChallengeRepository},
    routes::configure_routes,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // Load configuration
    let config = AppConfig::from_env().expect("Failed to load configuration");

    // Establish database connection
    let db_pool = establish_connection().expect("Failed to establish database connection");
    let db_pool = Arc::new(db_pool);

    // Create repositories
    let user_repo = Arc::new(PgUserRepository::new(Arc::clone(&db_pool)));
    let credential_repo = Arc::new(PgCredentialRepository::new(Arc::clone(&db_pool)));
    let challenge_repo = Arc::new(PgChallengeRepository::new(Arc::clone(&db_pool)));

    // Create WebAuthn service
    let webauthn_service = Arc::new(
        WebAuthnServiceImpl::new(
            &config.webauthn.rp_id,
            &config.webauthn.rp_name,
            &config.webauthn.rp_origin,
            user_repo,
            credential_repo,
            challenge_repo,
        )
        .expect("Failed to create WebAuthn service"),
    );

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