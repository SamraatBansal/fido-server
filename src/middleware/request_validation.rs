//! Request validation middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::{Bytes, Payload},
    Error,
};
use futures_util::future::LocalBoxFuture;
use std::future::ready;

/// Request validation middleware
pub struct RequestValidationMiddleware;

impl RequestValidationMiddleware {
    const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
}

impl<S, B> Transform<S, ServiceRequest> for RequestValidationMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestValidationMiddlewareService<S>;
    type InitError = ();
    type Future = ready::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestValidationMiddlewareService { service }))
    }
}

pub struct RequestValidationMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestValidationMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        
        Box::pin(async move {
            // Validate content type for POST/PUT requests
            if matches!(*req.method(), actix_web::http::Method::POST | actix_web::http::Method::PUT) {
                let content_type = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                // Only allow JSON content type
                if !content_type.starts_with("application/json") {
                    return Err(actix_web::error::ErrorBadRequest("Invalid content type. Only application/json is allowed."));
                }

                // Check content length
                if let Some(content_length) = req.headers().get("content-length") {
                    if let Ok(length_str) = content_length.to_str() {
                        if let Ok(length) = length_str.parse::<usize>() {
                            if length > RequestValidationMiddleware::MAX_REQUEST_SIZE {
                                return Err(actix_web::error::ErrorPayloadTooLarge("Request too large"));
                            }
                        }
                    }
                }
            }

            service.call(req).await
        })
    }
}