//! Security middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result, http::header};
use actix_web::dev::{Service, Transform};
use actix_web::middleware::DefaultHeaders;
use std::future::{ready, Ready};

/// Security headers middleware
pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add(header::StrictTransportSecurity, "max-age=31536000; includeSubDomains; preload")
        .add(header::XContentTypeOptions, "nosniff")
        .add(header::XFrameOptions, "DENY")
        .add(header::XXssProtection, "1; mode=block")
        .add(header::ContentSecurityPolicy, "default-src 'self'; script-src 'self' 'unsafe-inline'")
}

/// Rate limiting middleware placeholder
pub struct RateLimitMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitService { service }))
    }
}

pub struct RateLimitService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RateLimitService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = S::Future;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // TODO: Implement rate limiting logic
        self.service.call(req)
    }
}