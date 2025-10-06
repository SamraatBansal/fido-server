//! Security middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::dev::{forward_ready, Transform};
use actix_web::http::header;
use futures::future::{ready, LocalBoxFuture};
use std::task::{Context, Poll};

/// Security headers middleware
pub struct SecurityHeadersMiddleware;

impl SecurityHeadersMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddlewareService<S>;
    type InitError = ();
    type Future = ready::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddlewareService { service }))
    }
}

pub struct SecurityHeadersMiddlewareService<S> {
    service: S,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            
            // Add security headers
            res.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                "max-age=31536000; includeSubDomains".parse().unwrap(),
            );
            res.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff".parse().unwrap(),
            );
            res.headers_mut().insert(
                header::X_FRAME_OPTIONS,
                "DENY".parse().unwrap(),
            );
            res.headers_mut().insert(
                header::X_XSS_PROTECTION,
                "1; mode=block".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Referrer-Policy",
                "strict-origin-when-cross-origin".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Content-Security-Policy",
                "default-src 'self'".parse().unwrap(),
            );

            Ok(res)
        })
    }
}