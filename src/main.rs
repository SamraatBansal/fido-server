//! FIDO Server Main Entry Point

use actix_web::{middleware::Logger, App, HttpServer};
use std::io;

use fido_server::{
    config::AppConfig,
    middleware::{RateLimitMiddleware, SecurityHeaders, cors_config},
    routes::{api, webauthn},
    utils::AppState,
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let config = AppConfig::load();
    log::info!("Configuration loaded: {:?}", config.server);

    // Initialize application state
    let app_state = AppState::new(config.clone())
        .await
        .map_err(|e| {
            log::error!("Failed to initialize application state: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

    // Create rate limiter
    let rate_limiter = RateLimitMiddleware::new(config.security.rate_limit_requests_per_minute);

    log::info!("Server running at http://{}:{}", config.server.host, config.server.port);

    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::data::clone(&app_state.webauthn_service))
            .app_data(actix_web::data::clone(&app_state.user_service))
            .app_data(actix_web::data::clone(&app_state.credential_service))
            .wrap(Logger::default())
            .wrap(SecurityHeaders)
            .wrap(rate_limiter.clone())
            .wrap(cors_config())
            .configure(api::configure)
            .configure(webauthn::configure)
    })
    .bind((config.server.host, config.server.port))?
    .workers(config.server.workers.unwrap_or_else(num_cpus::get))
    .run()
    .await
}
