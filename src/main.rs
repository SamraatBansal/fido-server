//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, App, HttpServer, http::header};
use std::io;
use std::time::Duration;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    tracing::info!("Starting FIDO Server...");

    // TODO: Load configuration from config file
    let host = "127.0.0.1";
    let port = 8080;

    // TODO: Initialize database connection pool

    tracing::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS with security best practices
        let cors = Cors::default()
            .allowed_origin("http://localhost:8080")
            .allowed_origin("https://localhost:8080")
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .configure(fido2_webauthn_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
