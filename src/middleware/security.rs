//! Security middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::middleware::DefaultHeaders;
use actix_web::http::header;
use std::time::Duration;

/// Security headers middleware
pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add(header::StrictTransportSecurity, "max-age=31536000; includeSubDomains; preload")
        .add(header::XContentTypeOptions, "nosniff")
        .add(header::XFrameOptions, "DENY")
        .add(header::XXssProtection, "1; mode=block")
        .add(header::ReferrerPolicy, "strict-origin-when-cross-origin")
        .add(header::ContentSecurityPolicy, "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';")
        .add(header::PermissionsPolicy, "geolocation=(), microphone=(), camera=()")
}

/// Rate limiting middleware (placeholder)
pub fn rate_limit_middleware() -> impl actix_web::dev::Transform<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
    InitError = (),
> {
    // Placeholder implementation
    actix_web::middleware::Condition::new(false, actix_web::middleware::DefaultHeaders::new())
}

/// Request ID middleware (placeholder)
pub fn request_id() -> impl actix_web::dev::Transform<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
    InitError = (),
> {
    // Placeholder implementation
    actix_web::middleware::Condition::new(false, actix_web::middleware::DefaultHeaders::new())
}

/// CORS configuration
pub fn cors_config() -> actix_cors::Cors {
    use actix_cors::Cors;
    
    Cors::default()
        .allowed_origin_fn(|origin, _req_head| {
            // In production, you would have a whitelist of allowed origins
            // For now, allow localhost for development
            origin.starts_with("http://localhost") || 
            origin.starts_with("https://localhost") ||
            origin.starts_with("http://127.0.0.1") ||
            origin.starts_with("https://127.0.0.1")
        })
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::ORIGIN,
            header::USER_AGENT,
        ])
        .supports_credentials()
        .max_age(Duration::from_secs(3600))
        .expose_headers(vec!["X-Request-ID"])
}

/// Content size limit middleware
pub fn content_size_limit() -> actix_web::middleware::Condition<actix_web::middleware::DefaultHeaders> {
    actix_web::middleware::Condition::new(
        true, // Always apply
        actix_web::middleware::DefaultHeaders::new()
            .add(header::ContentLength, "1048576") // 1MB limit
    )
}