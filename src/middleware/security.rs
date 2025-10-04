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

/// Request ID middleware
pub fn request_id() -> impl actix_web::dev::Transform<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = Error,
    InitError = (),
> {
    use actix_web::dev::{Service, Transform, ServiceRequest, ServiceResponse};
    use actix_web::Error;
    use futures::future::{ok, Ready};
    use std::task::{Context, Poll};
    use uuid::Uuid;

    RequestIdMiddleware
}

struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestIdMiddlewareService<S>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Result<Self::Transform, Self::InitError> {
        Ok(RequestIdMiddlewareService { service })
    }
}

struct RequestIdMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestIdMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = futures::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let request_id = Uuid::new_v4().to_string();
        
        // Add request ID to request extensions
        req.extensions_mut().insert(request_id.clone());
        
        // Add request ID to response headers
        let fut = self.service.call(req);
        
        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut().insert("X-Request-ID", request_id.parse().unwrap());
            Ok(res)
        })
    }
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