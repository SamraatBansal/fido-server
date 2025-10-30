//! Security headers middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;
use std::future::ready;

/// Security headers middleware
pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
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

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        
        Box::pin(async move {
            let res = service.call(req).await?;
            
            // Add security headers
            let res = res.map_response(|mut response| {
                // Prevent clickjacking
                response.headers_mut().insert("X-Frame-Options", "DENY".parse().unwrap());
                
                // Prevent MIME type sniffing
                response.headers_mut().insert("X-Content-Type-Options", "nosniff".parse().unwrap());
                
                // Enable XSS protection
                response.headers_mut().insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
                
                // Content Security Policy
                response.headers_mut().insert(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';".parse().unwrap()
                );
                
                // Referrer Policy
                response.headers_mut().insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());
                
                // Permissions Policy
                response.headers_mut().insert(
                    "Permissions-Policy",
                    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()".parse().unwrap()
                );
                
                // Strict Transport Security (only on HTTPS)
                // Note: This should only be added when the connection is HTTPS
                // response.headers_mut().insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload".parse().unwrap());
                
                response
            });
            
            Ok(res)
        })
    }
}