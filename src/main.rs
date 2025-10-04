//! FIDO Server Main Entry Point

use actix_web::{App, HttpServer, middleware};
use fido_server::{
    config::settings::Settings,
    controllers::health_check,
    routes::{configure_api_routes, configure_health_routes},
    middleware::{configure_cors, security_headers},
    db::create_pool,
};
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let settings = Settings::new()
        .expect("Failed to load configuration");

    // Create database connection pool
    let db_pool = create_pool()
        .expect("Failed to create database pool");

    // Get server configuration
    let host = env::var("HOST").unwrap_or_else(|_| settings.server.host);
    let port = env::var("PORT")
        .unwrap_or_else(|_| settings.server.port.to_string())
        .parse()
        .unwrap_or(settings.server.port);

    log::info!("Server will run at http://{}:{}", host, port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Add database pool to app state
            .app_data(actix_web::web::Data::new(db_pool.clone()))
            // Add middleware
            .wrap(middleware::Logger::default())
            .wrap(security_headers())
            .wrap(configure_cors())
            // Configure routes
            .service(configure_health_routes())
            .service(configure_api_routes())
            // Legacy health endpoints for backward compatibility
            .route("/health", actix_web::web::get().to(health_check))
            .route("/api/v1/health", actix_web::web::get().to(health_check))
    })
    .bind((host.as_str(), port))?
    .workers(num_cpus::get())
    .run()
    .await
}