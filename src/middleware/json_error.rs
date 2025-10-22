//! Error handling middleware for JSON deserialization errors

use actix_web::{dev, error::JsonPayloadError, http::StatusCode, Error, HttpResponse, Result};
use crate::models::dto::ServerResponse;
use futures_util::future::{ok, Ready};

/// Middleware to handle JSON deserialization errors and return proper format
pub struct JsonErrorHandler;

impl dev::Middleware for JsonErrorHandler {
    type Service = JsonErrorHandlerService<S>;
    type Transform = JsonErrorHandlerTransform;
    type Response = HttpResponse;
    type Error = Error;
    type InitError = ();

    fn new_transform<S>(&self, service: S) -> Self::Transform
    where
        S: dev::Service<Request = dev::ServiceRequest, Response = HttpResponse, Error = Error>,
        S::Future: 'static,
    {
        JsonErrorHandlerTransform { service }
    }
}

pub struct JsonErrorHandlerTransform<S> {
    service: S,
}

impl<S> dev::Service for JsonErrorHandlerTransform<S>
where
    S: dev::Service<Request = dev::ServiceRequest, Response = HttpResponse, Error = Error>,
    S::Future: 'static,
{
    type Request = dev::ServiceRequest;
    type Response = HttpResponse;
    type Error = Error;
    type Future = futures_util::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, req: dev::ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        
        Box::pin(async move {
            // Try to call the service
            match service.call(req).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    // Check if it's a JSON deserialization error
                    if let Some(json_error) = error.as_error::<JsonPayloadError>() {
                        let message = match json_error {
                            JsonPayloadError::Deserialize(err) => {
                                format!("Invalid request format: {}", err)
                            }
                            JsonPayloadError::ContentType => {
                                "Invalid content type".to_string()
                            }
                            JsonPayloadError::Payload(err) => {
                                format!("Invalid payload: {}", err)
                            }
                            _ => {
                                "Invalid JSON request".to_string()
                            }
                        };

                        Ok(HttpResponse::BadRequest().json(ServerResponse::error(message)))
                    } else {
                        // Return the original error
                        Err(error)
                    }
                }
            }
        })
    }
}

pub struct JsonErrorHandlerService<S> {
    service: S,
}

// Helper function to create a proper error response for JSON errors
pub fn handle_json_error(error: &JsonPayloadError) -> HttpResponse {
    let message = match error {
        JsonPayloadError::Deserialize(err) => {
            format!("Invalid request format: {}", err)
        }
        JsonPayloadError::ContentType => {
            "Invalid content type".to_string()
        }
        JsonPayloadError::Payload(err) => {
            format!("Invalid payload: {}", err)
        }
        _ => {
            "Invalid JSON request".to_string()
        }
    };

    HttpResponse::BadRequest().json(ServerResponse::error(message))
}