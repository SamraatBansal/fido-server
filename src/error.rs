use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Invalid username format")]
    InvalidUsername,
    
    #[error("Invalid credential ID")]
    InvalidCredentialId,
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Invalid attestation")]
    InvalidAttestation,
    
    #[error("Invalid assertion")]
    InvalidAssertion,
    
    #[error("Replay attack detected")]
    ReplayAttack,
    
    #[error("Origin mismatch")]
    OriginMismatch,
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, error_message) = match self {
            AppError::InvalidRequest(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg.clone()),
            AppError::UserNotFound(msg) => (actix_web::http::StatusCode::NOT_FOUND, msg.clone()),
            AppError::InvalidUsername => (actix_web::http::StatusCode::BAD_REQUEST, "Invalid username format".to_string()),
            AppError::InvalidCredentialId => (actix_web::http::StatusCode::BAD_REQUEST, "Invalid credential ID".to_string()),
            AppError::InvalidChallenge => (actix_web::http::StatusCode::BAD_REQUEST, "Invalid challenge".to_string()),
            AppError::InvalidAttestation => (actix_web::http::StatusCode::BAD_REQUEST, "Can not validate response signature!".to_string()),
            AppError::InvalidAssertion => (actix_web::http::StatusCode::BAD_REQUEST, "Can not validate response signature!".to_string()),
            AppError::ReplayAttack => (actix_web::http::StatusCode::BAD_REQUEST, "Replay attack detected".to_string()),
            AppError::OriginMismatch => (actix_web::http::StatusCode::BAD_REQUEST, "Origin mismatch".to_string()),
            AppError::Database(msg) => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", msg)),
            AppError::WebAuthn(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Serialization(msg) => (actix_web::http::StatusCode::BAD_REQUEST, format!("Serialization error: {}", msg)),
            AppError::Internal(msg) => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
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
        AppError::InvalidRequest(format!("Base64 decode error: {}", err))
    }
}