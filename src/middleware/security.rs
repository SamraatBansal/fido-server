use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::Error,
    HttpMessage,
};
use std::future::{ready, Ready};

pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

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
                "X-Content-Type-Options",
                "nosniff".parse().unwrap(),
            );
            res.headers_mut().insert(
                "X-Frame-Options",
                "DENY".parse().unwrap(),
            );
            res.headers_mut().insert(
                "X-XSS-Protection",
                "1; mode=block".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Content-Security-Policy",
                "default-src 'self'".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Referrer-Policy",
                "strict-origin-when-cross-origin".parse().unwrap(),
            );
            res.headers_mut().insert(
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=()".parse().unwrap(),
            );
            
            Ok(res)
        })
    }
}