//! CORS middleware

use actix_cors::Cors;
use actix_web::dev::ServiceRequest;
use actix_web::Error;
use crate::config::SecurityConfig;

/// CORS middleware configuration
pub struct CorsMiddleware;

impl CorsMiddleware {
    /// Create CORS configuration
    pub fn configure(config: &SecurityConfig) -> Cors {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                "Authorization",
                "Accept",
                "Content-Type",
                "X-Requested-With",
                "User-Agent",
            ])
            .supports_credentials()
            .max_age(3600);

        // Configure allowed origins
        if config.cors_origins.is_empty() {
            cors = cors.allow_any_origin();
        } else {
            for origin in &config.cors_origins {
                cors = cors.allowed_origin(origin);
            }
        }

        cors
    }
}