//! CORS middleware configuration

use actix_cors::Cors;
use actix_web::http::header;

/// Configure CORS middleware
pub fn configure_cors() -> Cors {
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