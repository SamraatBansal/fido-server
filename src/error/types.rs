//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use diesel::result::Error as DieselError;
use std::fmt;
use thiserror::Error;
use validator::ValidationErrors;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Debug, Error)]
pub enum AppError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] DieselError),
    
    /// Database error with custom message
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    /// WebAuthn error
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    /// Validation error
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationErrors),
    
    /// Challenge not found or expired
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    /// Invalid credential
    #[error("Invalid credential")]
    InvalidCredential,
    
    /// User not found
    #[error("User not found")]
    UserNotFound,
    
    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Internal server error
    #[error("Internal server error: {0}")]
    Internal(String),
    
    /// Bad request error
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Base64 encoding/decoding error
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    
    /// URL parsing error
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = self.to_string();

        // Don't expose internal errors in production
        let error_response = match self {
            AppError::Database(_) | AppError::Internal(_) => {
                serde_json::json!({
                    "error": "Internal server error",
                    "status": status_code.as_u16()
                })
            }
            _ => {
                serde_json::json!({
                    "error": error_message,
                    "status": status_code.as_u16()
                })
            }
        };

        HttpResponse::build(status_code).json(error_response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Database(_) | Self::DatabaseError(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthn(_) | Self::Validation(_) | Self::BadRequest(_) | 
            Self::Serialization(_) | Self::Base64(_) | Self::Url(_) => StatusCode::BAD_REQUEST,
            Self::ChallengeNotFound | Self::InvalidCredential | Self::UserNotFound | Self::NotFound(_) => {
                StatusCode::NOT_FOUND
            }
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for AppError {}
