//! Error handling module

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

/// Application error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        use crate::schema::ServerResponse;
        
        let (status, message) = match self {
            AppError::WebAuthn(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::Validation(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::NotFound(msg) => {
                (actix_web::http::StatusCode::NOT_FOUND, msg.as_str())
            }
            AppError::Internal(_msg) => {
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let response = ServerResponse::error(message);
        HttpResponse::build(status).json(response)
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, AppError>;