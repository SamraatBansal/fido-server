//! Security headers middleware (simplified)

use actix_web::http::header;

/// Get security headers as a header map
pub fn security_headers() -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::HeaderName::from_static("x-xss-protection"), "1; mode=block".parse().unwrap());
    headers.insert(
        header::HeaderName::from_static("strict-transport-security"),
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        "default-src 'self'".parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );
    headers
}