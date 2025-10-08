//! Error handling middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error as ActixError,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};
use tracing::{error, warn};

use crate::error::AppError;

/// Error handling middleware
pub struct ErrorHandler;

impl<S, B> Transform<S, ServiceRequest> for ErrorHandler
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = ErrorHandlerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ErrorHandlerMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct ErrorHandlerMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for ErrorHandlerMiddleware<S>
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
            let path = req.path().to_string();
            let method = req.method().to_string();
            
            match service.call(req).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    // Log the error with context
                    match error.as_error::<AppError>() {
                        Some(app_error) => {
                            match app_error {
                                AppError::ValidationError(msg) => {
                                    warn!("Validation error on {} {}: {}", method, path, msg);
                                }
                                AppError::BadRequest(msg) => {
                                    warn!("Bad request on {} {}: {}", method, path, msg);
                                }
                                AppError::NotFound(msg) => {
                                    warn!("Not found on {} {}: {}", method, path, msg);
                                }
                                AppError::Unauthorized(msg) => {
                                    warn!("Unauthorized on {} {}: {}", method, path, msg);
                                }
                                AppError::RateLimitExceeded(msg) => {
                                    warn!("Rate limit exceeded on {} {}: {}", method, path, msg);
                                }
                                AppError::WebAuthnError(msg) => {
                                    warn!("WebAuthn error on {} {}: {}", method, path, msg);
                                }
                                AppError::DatabaseError(msg) => {
                                    error!("Database error on {} {}: {}", method, path, msg);
                                }
                                AppError::InternalError(msg) => {
                                    error!("Internal error on {} {}: {}", method, path, msg);
                                }
                            }
                        }
                        None => {
                            error!("Unexpected error on {} {}: {}", method, path, error);
                        }
                    }
                    
                    Err(error)
                }
            }
        })
    }
}