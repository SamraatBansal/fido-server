//! Logging middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::dev::{Service, Transform};
use std::future::{ready, Ready};
use std::time::Instant;

/// Request logging middleware
pub struct RequestLogger;

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLoggerService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerService { service }))
    }
}

pub struct RequestLoggerService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = S::Future;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start = Instant::now();
        let method = req.method().clone();
        let path = req.path().to_string();
        
        // Log request start
        log::info!("{} {} - Starting", method, path);
        
        let future = self.service.call(req);
        
        // Note: In a real implementation, you'd want to use middleware that can
        // intercept the response to log completion time and status
        future
    }
}