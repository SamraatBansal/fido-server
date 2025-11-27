//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use fido_server::{AppState, config::Settings};
use std::io;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let config = Settings::new().map_err(|e| {
        log::error!("Failed to load configuration: {}", e);
        io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
    })?;
    
    let host = config.server.host.clone();
    let port = config.server.port;

    // Initialize application state (database and Redis connections)
    let app_state = AppState::new(config).await.map_err(|e| {
        log::error!("Failed to initialize application state: {}", e);
        io::Error::new(io::ErrorKind::Other, e.to_string())
    })?;

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
