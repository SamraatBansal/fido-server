//! Error handling module

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

/// Application error type
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),

    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Challenge not found or expired: {0}")]
    ChallengeNotFound(String),

    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Registration failed: {0}")]
    RegistrationFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Configuration error: {0}")]
    Configuration(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            AppError::InvalidInput(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::UserNotFound(_) | AppError::CredentialNotFound(_) | AppError::ChallengeNotFound(_) => {
                actix_web::http::StatusCode::NOT_FOUND
            }
            AppError::InvalidChallenge(_) | AppError::AuthenticationFailed(_) | AppError::RegistrationFailed(_) => {
                actix_web::http::StatusCode::UNAUTHORIZED
            }
            AppError::WebAuthn(_) | AppError::Database(_) | AppError::DatabaseConnection(_) | 
            AppError::Serialization(_) | AppError::Internal(_) | AppError::Configuration(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        HttpResponse::build(status).json(crate::models::ServerResponse {
            status: "failed".to_string(),
            error_message: self.to_string(),
        })
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, AppError>;