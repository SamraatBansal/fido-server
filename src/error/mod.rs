//! Error module

use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

/// Application error type
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    BadRequest(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::BadRequest(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::InternalError(msg) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "failed", 
                    "errorMessage": msg
                }))
            }
            AppError::WebAuthnError(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::SerializationError(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Invalid JSON format"
                }))
            }
        }
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, AppError>;