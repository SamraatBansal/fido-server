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
    WebAuthnError(String),
    /// Validation error
    ValidationError(String),
    /// Not found error
    NotFound(String),
    /// Internal server error
    InternalError(String),
    /// Bad request error
    BadRequest(String),
    /// Unauthorized error
    Unauthorized(String),
    /// Challenge expired error
    ChallengeExpired(String),
    /// Invalid challenge error
    InvalidChallenge(String),
    /// Credential already exists error
    CredentialAlreadyExists(String),
    /// Invalid signature error
    InvalidSignature(String),
    /// Rate limit exceeded error
    RateLimitExceeded(String),
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
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            Self::ChallengeExpired(msg) => write!(f, "Challenge expired: {msg}"),
            Self::InvalidChallenge(msg) => write!(f, "Invalid challenge: {msg}"),
            Self::CredentialAlreadyExists(msg) => write!(f, "Credential already exists: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "Invalid signature: {msg}"),
            Self::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {msg}"),
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
            Self::ChallengeExpired(_) => StatusCode::BAD_REQUEST,
            Self::InvalidChallenge(_) => StatusCode::BAD_REQUEST,
            Self::CredentialAlreadyExists(_) => StatusCode::CONFLICT,
            Self::InvalidSignature(_) => StatusCode::UNAUTHORIZED,
            Self::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

impl std::error::Error for AppError {}
