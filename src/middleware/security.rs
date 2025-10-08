//! Security headers middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::Error,
    http::header,
    Error as ActixError,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};

/// Security headers middleware
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        
        Box::pin(async move {
            let res = service.call(req).await?;
            Ok(res.map_body(|_, body| {
                // Add security headers
                res.headers_mut().insert(
                    header::X_CONTENT_TYPE_OPTIONS,
                    "nosniff".parse().unwrap(),
                );
                res.headers_mut().insert(
                    header::X_FRAME_OPTIONS,
                    "DENY".parse().unwrap(),
                );
                res.headers_mut().insert(
                    header::HeaderName::from_static("x-xss-protection"),
                    "1; mode=block".parse().unwrap(),
                );
                res.headers_mut().insert(
                    header::HeaderName::from_static("strict-transport-security"),
                    "max-age=31536000; includeSubDomains".parse().unwrap(),
                );
                res.headers_mut().insert(
                    header::HeaderName::from_static("content-security-policy"),
                    "default-src 'self'".parse().unwrap(),
                );
                res.headers_mut().insert(
                    header::HeaderName::from_static("referrer-policy"),
                    "strict-origin-when-cross-origin".parse().unwrap(),
                );
                res.headers_mut().insert(
                    header::HeaderName::from_static("permissions-policy"),
                    "geolocation=(), microphone=(), camera=()".parse().unwrap(),
                );
                
                body
            }))
        })
    }
}

/// Get security headers as a header map (for manual application)
pub fn security_headers() -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'".parse().unwrap(),
    );
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );
    headers
}