//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, App, HttpServer};
use fido_server::{config::Settings, routes::api, AppState};
use std::io;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let settings = Settings::new().unwrap_or_else(|e| {
        eprintln!("Failed to load configuration: {}", e);
        std::process::exit(1);
    });

    // Initialize application state
    let app_state = AppState::new(&settings).unwrap_or_else(|e| {
        eprintln!("Failed to initialize application state: {}", e);
        std::process::exit(1);
    });

    let host = settings.server.host.clone();
    let port = settings.server.port;

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(actix_web::web::Data::new(app_state.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
