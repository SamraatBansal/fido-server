//! CORS middleware configuration

use actix_cors::Cors;
use actix_web::dev::ServiceRequest;
use actix_web::Error;
use crate::config::ServerConfig;

/// Configure CORS middleware
pub fn configure_cors(config: &ServerConfig) -> Cors {
    let mut cors = Cors::default();

    // Add allowed origins
    for origin in &config.allowed_origins {
        cors = cors.allowed_origin(origin);
    }

    cors
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            "Authorization",
            "Accept",
            "Content-Type",
            "Origin",
            "User-Agent",
            "Cache-Control",
            "Connection",
        ])
        .supports_credentials()
        .max_age(3600)
}