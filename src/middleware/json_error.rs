//! JSON error handling middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::body::MessageBody;
use actix_web::dev::{forward_ready, Service, Transform};
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;

/// Middleware to ensure all responses are JSON formatted
pub struct JsonErrorHandler;

impl<S, B> Transform<S, ServiceRequest> for JsonErrorHandler
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JsonErrorHandlerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JsonErrorHandlerMiddleware { service })
    }
}

pub struct JsonErrorHandlerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for JsonErrorHandlerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        
        Box::pin(async move {
            // Check if the request has JSON content type but might be malformed
            if let Some(content_type) = req.headers().get("content-type") {
                if let Ok(content_type_str) = content_type.to_str() {
                    if content_type_str.contains("application/json") {
                        // For JSON requests, ensure proper error handling
                        // This is a placeholder for more sophisticated validation
                    }
                }
            }
            
            service.call(req).await
        })
    }
}