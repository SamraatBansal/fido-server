use crate::config::SecurityConfig;
use axum::{
    http::{HeaderValue, Method, StatusCode},
    response::Response,
};
use std::collections::HashSet;
use tower_http::cors::{Any, CorsLayer};

pub fn cors_layer(config: &SecurityConfig) -> CorsLayer {
    let allowed_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    if config.cors_enabled {
        CorsLayer::new()
            .allow_origin(allowed_origins)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
            .allow_credentials(true)
    } else {
        CorsLayer::very_permissive()
    }
}

pub async fn security_headers(
    mut response: Response,
) -> Response {
    let headers = response.headers_mut();
    
    // Security headers
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none';"),
    );

    response
}

use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::sync::Arc;
use std::time::Duration;

pub type AppRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

pub fn create_rate_limiter(config: &SecurityConfig) -> Arc<AppRateLimiter> {
    let quota = Quota::with_period(Duration::from_secs(config.rate_limit.window_seconds))
        .unwrap()
        .allow_burst(std::num::NonZeroU32::new(config.rate_limit.burst_size).unwrap());

    Arc::new(RateLimiter::keyed(quota))
}

pub fn rate_limiting() -> tower::ServiceBuilder<
    tower::util::MapResponseLayer<
        fn(Response) -> Response,
    >,
> {
    tower::ServiceBuilder::new()
        .map_response(|response: Response| {
            // Rate limiting logic would go here
            // For now, just pass through
            response
        })
}