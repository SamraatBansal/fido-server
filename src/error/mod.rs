use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Authorization error: {0}")]
    Authorization(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Challenge error: {0}")]
    Challenge(String),
    
    #[error("Credential error: {0}")]
    Credential(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, error_message) = match self {
            AppError::Validation(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg),
            AppError::Authentication(msg) => (actix_web::http::StatusCode::UNAUTHORIZED, msg),
            AppError::Authorization(msg) => (actix_web::http::StatusCode::FORBIDDEN, msg),
            AppError::NotFound(msg) => (actix_web::http::StatusCode::NOT_FOUND, msg),
            AppError::Conflict(msg) => (actix_web::http::StatusCode::CONFLICT, msg),
            AppError::WebAuthn(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg),
            AppError::Challenge(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg),
            AppError::Credential(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg),
            _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, &"Internal server error".to_string()),
        };

        HttpResponse::build(status_code).json(json!({
            "status": "failed",
            "errorMessage": error_message
        }))
    }
}

// Conversion implementations for common error types
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Serialization(err.to_string())
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        AppError::Validation(format!("Invalid base64 encoding: {}", err))
    }
}