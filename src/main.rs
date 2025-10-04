//! FIDO Server Main Entry Point

use actix_web::{App, HttpServer, middleware};
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server v{}", env!("CARGO_PKG_VERSION"));

    // For now, use a simple configuration
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);

    log::info!("Server will run at http://{}:{}", host, port);

    // Start HTTP server with basic health check
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .route("/health", actix_web::web::get().to(health_check))
            .route("/api/v1/health", actix_web::web::get().to(health_check))
    })
    .bind((host.as_str(), port))?
    .workers(num_cpus::get())
    .run()
    .await
}

/// Simple health check endpoint
async fn health_check() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}