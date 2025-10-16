//! Error types for the FIDO2/WebAuthn server

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;
use diesel::result::Error as DieselError;

/// Application error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] DieselError),

    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),

    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),

    #[error("Invalid assertion: {0}")]
    InvalidAssertion(String),

    #[error("User already exists: {0}")]
    UserExists(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        use crate::schema::ServerResponse;
        
        let (status, message) = match self {
            AppError::Database(err) => {
                log::error!("Database error: {:?}", err);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::WebAuthn(msg) => {
                log::warn!("WebAuthn error: {}", msg);
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::Validation(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::NotFound(msg) => {
                (actix_web::http::StatusCode::NOT_FOUND, msg.as_str())
            }
            AppError::Unauthorized(msg) => {
                (actix_web::http::StatusCode::UNAUTHORIZED, msg.as_str())
            }
            AppError::RateLimitExceeded => {
                (actix_web::http::StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
            }
            AppError::Internal(msg) => {
                log::error!("Internal error: {}", msg);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::InvalidChallenge(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::InvalidAttestation(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::InvalidAssertion(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::UserExists(msg) => {
                (actix_web::http::StatusCode::CONFLICT, msg.as_str())
            }
            AppError::Config(msg) => {
                log::error!("Configuration error: {}", msg);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Configuration error")
            }
        };

        let response = ServerResponse::error(message);
        HttpResponse::build(status).json(response)
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, AppError>;