//! Security headers middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error, HttpResponse,
};
use futures::future::LocalBoxFuture;
use std::future::ready;

/// Security headers middleware
pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = ready::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersService { service }))
    }
}

pub struct SecurityHeadersService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
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
                header::HeaderName::from_static("x-content-type-options"),
                header::HeaderValue::from_static("nosniff"),
            );
            
            res.headers_mut().insert(
                header::HeaderName::from_static("x-frame-options"),
                header::HeaderValue::from_static("DENY"),
            );
            
            res.headers_mut().insert(
                header::HeaderName::from_static("x-xss-protection"),
                header::HeaderValue::from_static("1; mode=block"),
            );
            
            res.headers_mut().insert(
                header::HeaderName::from_static("strict-transport-security"),
                header::HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
            );
            
            res.headers_mut().insert(
                header::HeaderName::from_static("referrer-policy"),
                header::HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            
            res.headers_mut().insert(
                header::HeaderName::from_static("content-security-policy"),
                header::HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"),
            );
            
            res.headers_mut().insert(
                header::HeaderName::from_static("permissions-policy"),
                header::HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
            );

            Ok(res)
        })
    }
}

/// Simple security headers function for use with actix-web middleware
pub async fn security_headers(
    req: actix_web::HttpRequest,
    next: actix_web::dev::Payload,
) -> Result<HttpResponse, Error> {
    let mut res = actix_web::dev::ServiceResponse::new(
        req.clone(),
        HttpResponse::Ok().finish(),
    );
    
    // Add security headers
    res.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    
    res.headers_mut().insert(
        header::HeaderName::from_static("x-frame-options"),
        header::HeaderValue::from_static("DENY"),
    );
    
    res.headers_mut().insert(
        header::HeaderName::from_static("x-xss-protection"),
        header::HeaderValue::from_static("1; mode=block"),
    );
    
    res.headers_mut().insert(
        header::HeaderName::from_static("strict-transport-security"),
        header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    Ok(res.into())
}