//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;
use std::sync::Arc;

use fido_server::controllers::WebAuthnController;
use fido_server::webauthn::{WebAuthnConfig, WebAuthnServiceImpl};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let webauthn_config = WebAuthnConfig::default();
    
    // Try to use database service if DATABASE_URL is provided, otherwise use in-memory
    let webauthn_service: Arc<dyn WebAuthnService> = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        log::info!("Using database-backed WebAuthn service");
        let pool = fido_server::db::establish_connection(&database_url)
            .expect("Failed to establish database connection");
        
        let user_repo = Arc::new(fido_server::schema::UserRepository::new(pool.clone()));
        let credential_repo = Arc::new(fido_server::schema::CredentialRepository::new(pool.clone()));
        let challenge_repo = Arc::new(fido_server::schema::ChallengeRepository::new(pool));
        
        Arc::new(DatabaseWebAuthnService::new(
            webauthn_config,
            user_repo,
            credential_repo,
            challenge_repo,
        ))
    } else {
        log::info!("Using in-memory WebAuthn service");
        Arc::new(WebAuthnServiceImpl::new(webauthn_config))
    };
    
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

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
            .app_data(web::Data::new(webauthn_controller.clone()))
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
