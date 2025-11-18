//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use std::fmt;
use webauthn_rs::prelude::WebauthnError;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    /// WebAuthn error
    #[error("WebAuthn error: {0}")]
    WebAuthnError(#[from] WebauthnError),
    
    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Internal server error
    #[error("Internal error: {0}")]
    InternalError(String),
    
    /// Bad request error
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    /// Security error
    #[error("Security error: {0}")]
    SecurityError(String),
    
    /// Challenge error
    #[error("Challenge error: {0}")]
    ChallengeError(String),
    
    /// Credential error
    #[error("Credential error: {0}")]
    CredentialError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            Self::WebAuthnError(msg) => write!(f, "WebAuthn error: {msg}"),
            Self::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            Self::NotFound(msg) => write!(f, "Not found: {msg}"),
            Self::InternalError(msg) => write!(f, "Internal error: {msg}"),
            Self::BadRequest(msg) => write!(f, "Bad request: {msg}"),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = self.to_string();

        HttpResponse::build(status_code).json(serde_json::json!({
            "error": error_message,
            "status": status_code.as_u16()
        }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseError(_) | Self::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthnError(_) => StatusCode::BAD_REQUEST,
            Self::ValidationError(_) | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

impl std::error::Error for AppError {}
