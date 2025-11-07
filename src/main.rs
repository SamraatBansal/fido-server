//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;
use std::sync::Arc;

use fido_server::{
    config::Settings,
    db::establish_connection,
    controllers::registration::AppState,
    services::WebAuthnService,
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let settings = Settings::new().expect("Failed to load configuration");
    
    let host = &settings.server.host;
    let port = settings.server.port;

    // Initialize database connection pool
    let db_pool = establish_connection(&settings.database.url)
        .expect("Failed to create database connection pool");
    let db_pool = Arc::new(db_pool);

    // Initialize WebAuthn service
    let webauthn_service = WebAuthnService::new(&settings.webauthn, db_pool.clone())
        .expect("Failed to create WebAuthn service");

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        // Create application state
        let app_state = AppState {
            webauthn_service: webauthn_service.clone(),
            db_pool: db_pool.clone(),
        };

        App::new()
            .app_data(web::Data::new(app_state))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(fido_server::routes::api::configure)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
