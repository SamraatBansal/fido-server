//! Error handling module

use actix_web::{error::ResponseError, HttpResponse};
use serde_json::json;
use thiserror::Error;

/// Application error types
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Connection error: {0}")]
    Connection(#[from] diesel::result::ConnectionError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_response = json!({
            "status": "failed",
            "errorMessage": self.to_string()
        });

        HttpResponse::build(status_code).json(error_response)
    }
}

impl AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AppError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => actix_web::http::StatusCode::FORBIDDEN,
            AppError::NotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            AppError::Conflict(_) => actix_web::http::StatusCode::CONFLICT,
            AppError::WebAuthn(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::Database(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Connection(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Serialization(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, AppError>;