//! Security middleware

use actix_web::{dev::ServiceRequest, Error, Result};
use actix_web::http::header;
use std::time::Duration;

/// Security headers middleware
pub fn security_headers() -> impl Fn(ServiceRequest, Result) -> Result {
    |req: ServiceRequest, res: Result| {
        if let Ok(mut response) = res {
            // Add security headers
            response.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                "max-age=31536000; includeSubDomains".parse().unwrap(),
            );
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().unwrap(),
            );
            response.headers_mut().insert(
                header::X_FRAME_OPTIONS,
                "DENY".parse().unwrap(),
            );
            response.headers_mut().insert(
                header::X_XSS_PROTECTION,
                "1; mode=block".parse().unwrap(),
            );
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'".parse().unwrap(),
            );
        }
        res
    }
}

/// Rate limiting middleware (placeholder)
pub fn rate_limiter() -> impl Fn(ServiceRequest, Result) -> Result {
    |req: ServiceRequest, res: Result| {
        // TODO: Implement proper rate limiting
        // For now, just pass through
        res
    }
}

/// Request size limit middleware
pub fn request_size_limit() -> impl Fn(ServiceRequest, Result) -> Result {
    |req: ServiceRequest, res: Result| {
        // Check content-length header if present
        if let Some(content_length) = req.headers().get(header::CONTENT_LENGTH) {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    // Limit request size to 1MB
                    if length > 1024 * 1024 {
                        return Err(Error::from(actix_web::error::ErrorPayloadTooLarge("Request too large")));
                    }
                }
            }
        }
        res
    }
}