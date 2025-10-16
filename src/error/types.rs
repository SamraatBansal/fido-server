//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use std::fmt;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Debug)]
pub enum AppError {
    /// Database error
    DatabaseError(String),
    /// WebAuthn error
    WebAuthn(String),
    /// Validation error
    ValidationError(String),
    /// Not found error
    NotFound(String),
    /// Internal server error
    InternalError(String),
    /// Bad request error
    BadRequest(String),
    /// Configuration error
    Configuration(String),
    /// Invalid request
    InvalidRequest(String),
    /// User not found
    UserNotFound(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            Self::WebAuthn(msg) => write!(f, "WebAuthn error: {msg}"),
            Self::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            Self::NotFound(msg) => write!(f, "Not found: {msg}"),
            Self::InternalError(msg) => write!(f, "Internal error: {msg}"),
            Self::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            Self::Configuration(msg) => write!(f, "Configuration error: {msg}"),
            Self::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            Self::UserNotFound(msg) => write!(f, "User not found: {msg}"),
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
            Self::DatabaseError(_) | Self::InternalError(_) | Self::Configuration(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthn(_) | Self::ValidationError(_) | Self::BadRequest(_) | Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) | Self::UserNotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

impl std::error::Error for AppError {}
