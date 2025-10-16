//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use crate::domain::dto::ServerResponse;
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
    /// Challenge expired
    ChallengeExpired,
    /// Invalid signature
    InvalidSignature,
    /// User already exists
    UserAlreadyExists,
    /// User does not exist
    UserDoesNotExist,
    /// Credential already exists
    CredentialAlreadyExists,
    /// Rate limited
    RateLimited,
    /// Security violation
    SecurityViolation,
    /// Invalid origin
    InvalidOrigin,
    /// Origin not allowed
    OriginNotAllowed,
    /// Invalid username
    InvalidUsername,
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
            Self::ChallengeExpired => write!(f, "Challenge has expired"),
            Self::InvalidSignature => write!(f, "Can not validate response signature!"),
            Self::UserAlreadyExists => write!(f, "User already exists"),
            Self::UserDoesNotExist => write!(f, "User does not exists!"),
            Self::CredentialAlreadyExists => write!(f, "Credential already exists"),
            Self::RateLimited => write!(f, "Rate limit exceeded"),
            Self::SecurityViolation => write!(f, "Security violation detected"),
            Self::InvalidOrigin => write!(f, "Invalid origin"),
            Self::OriginNotAllowed => write!(f, "Origin not allowed"),
            Self::InvalidUsername => write!(f, "Invalid username"),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = self.to_string();

        // Return FIDO2 compliant response format
        let response = ServerResponse::error(error_message);
        
        HttpResponse::build(status_code).json(response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseError(_) | Self::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthnError(_)
            | Self::ValidationError(_)
            | Self::BadRequest(_)
            | Self::InvalidSignature
            | Self::ChallengeExpired
            | Self::UserAlreadyExists
            | Self::CredentialAlreadyExists
            | Self::SecurityViolation
            | Self::InvalidOrigin
            | Self::OriginNotAllowed
            | Self::InvalidUsername => StatusCode::BAD_REQUEST,
            Self::NotFound(_) | Self::UserDoesNotExist => StatusCode::NOT_FOUND,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

impl std::error::Error for AppError {}

// Convert from common error types
impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        AppError::ValidationError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::BadRequest(format!("JSON parsing error: {}", err))
    }
}
