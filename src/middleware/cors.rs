//! CORS configuration middleware

use actix_cors::Cors;
use actix_web::http::header;
use crate::config::AppConfig;

/// Create CORS configuration based on application config
pub fn create_cors(config: &AppConfig) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
        ])
        .supports_credentials()
        .max_age(3600);

    // Add allowed origins from config
    for origin in &config.security.allowed_origins {
        cors = cors.allowed_origin(origin);
    }

    cors
}

/// Default CORS configuration for development
pub fn default_cors() -> Cors {
    Cors::default()
        .allowed_origin("http://localhost:3000")
        .allowed_origin("http://localhost:8080")
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
        ])
        .supports_credentials()
        .max_age(3600)
}