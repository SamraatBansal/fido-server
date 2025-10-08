//! FIDO Server Main Entry Point

use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;

use fido_server::{
    config::Settings,
    db::establish_connection,
    middleware::{cors_config, security_headers},
    routes::api::configure,
    services::WebAuthnService,
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load configuration
    let settings = Settings::new()
        .expect("Failed to load configuration");

    tracing::info!("Starting FIDO Server...");
    tracing::info!("Configuration: {:?}", settings);

    // Initialize database connection pool
    let db_pool = establish_connection(&settings.database.url)
        .expect("Failed to establish database connection");

    // Initialize WebAuthn service
    let webauthn_service = WebAuthnService::new(
        &settings.webauthn.rp_id,
        &settings.webauthn.rp_name,
        &settings.webauthn.origin,
        db_pool.clone(),
    )
    .expect("Failed to initialize WebAuthn service");

    let host = settings.server.host.clone();
    let port = settings.server.port;

    tracing::info!("Server running at http://{}:{}", host, port);

    // Run HTTP server
    HttpServer::new(move || {
        App::new()
            // Add data
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(web::Data::new(settings.clone()))
            // Add middleware
            .wrap(ErrorHandler)
            .wrap(SecurityHeaders)
            .wrap(cors_config())
            .wrap(Logger::new("%a %{User-Agent}i %r %s %b %D"))
            // Configure routes
            .configure(configure)
            // Health check endpoint
            .route("/health", web::get().to(health_check))
    })
    .bind((host, port))?
    .run()
    .await
}

/// Health check endpoint
async fn health_check() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "service": "fido-server"
    }))
}