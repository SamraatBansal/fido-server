//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use fido_server::config::Settings;
use fido_server::db::create_pool;
use fido_server::utils::AppState;
use std::io;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

fn run_migrations(database_url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    use diesel::prelude::*;
    
    let mut connection = diesel::PgConnection::establish(database_url)?;
    connection.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let settings = Settings::load().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to load settings: {}", e))
    })?;

    // Run database migrations
    if let Err(e) = run_migrations(&settings.database.url) {
        log::error!("Failed to run migrations: {}", e);
        return Err(io::Error::new(io::ErrorKind::Other, format!("Migration failed: {}", e)));
    }
    log::info!("Database migrations completed successfully");

    // Create app state
    let app_state = AppState::new(&settings).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to create app state: {}", e))
    })?;

    let host = settings.server.host.clone();
    let port = settings.server.port;

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allowed_origin("http://localhost:8080")
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:3001") 
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(app_state.webauthn_service.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(fido_server::routes::api::configure)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
