//! Error handling module

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use diesel::result::Error as DieselError;
use serde_json::json;
use std::fmt;
use thiserror::Error;
use webauthn_rs::error::WebauthnError;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Error, Debug)]
pub enum AppError {
    /// WebAuthn related errors
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebauthnError),

    /// Database related errors
    #[error("Database error: {0}")]
    Database(#[from] DieselError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Authorization errors
    #[error("Authorization error: {0}")]
    Authorization(String),

    /// Not found errors
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Conflict errors
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Rate limit errors
    #[error("Rate limit exceeded")]
    RateLimit,

    /// JWT errors
    #[error("JWT error: {0}")]
    Jwt(String),

    /// CSRF errors
    #[error("CSRF error: {0}")]
    Csrf(String),

    /// Internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Bad request errors
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Timeout errors
    #[error("Request timeout")]
    Timeout,

    /// Service unavailable errors
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 encoding/decoding errors
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// UUID parsing errors
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    /// Time parsing errors
    #[error("Time error: {0}")]
    Time(#[from] chrono::ParseError),

    /// URL parsing errors
    #[error("URL error: {0}")]
    Url(String),
}

impl AppError {
    /// Get error category for logging
    pub fn category(&self) -> &'static str {
        match self {
            AppError::WebAuthn(_) => "webauthn",
            AppError::Database(_) => "database",
            AppError::Config(_) => "config",
            AppError::Validation(_) => "validation",
            AppError::Authentication(_) => "authentication",
            AppError::Authorization(_) => "authorization",
            AppError::NotFound(_) => "not_found",
            AppError::Conflict(_) => "conflict",
            AppError::RateLimit => "rate_limit",
            AppError::Jwt(_) => "jwt",
            AppError::Csrf(_) => "csrf",
            AppError::Internal(_) => "internal",
            AppError::BadRequest(_) => "bad_request",
            AppError::Timeout => "timeout",
            AppError::ServiceUnavailable(_) => "service_unavailable",
            AppError::Io(_) => "io",
            AppError::Json(_) => "json",
            AppError::Base64(_) => "base64",
            AppError::Uuid(_) => "uuid",
            AppError::Time(_) => "time",
            AppError::Url(_) => "url",
        }
    }

    /// Check if error is client error (4xx)
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            AppError::Validation(_)
                | AppError::Authentication(_)
                | AppError::Authorization(_)
                | AppError::NotFound(_)
                | AppError::Conflict(_)
                | AppError::RateLimit
                | AppError::Jwt(_)
                | AppError::Csrf(_)
                | AppError::BadRequest(_)
                | AppError::Timeout
        )
    }

    /// Check if error is server error (5xx)
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            AppError::WebAuthn(_)
                | AppError::Database(_)
                | AppError::Config(_)
                | AppError::Internal(_)
                | AppError::ServiceUnavailable(_)
                | AppError::Io(_)
                | AppError::Json(_)
                | AppError::Base64(_)
                | AppError::Uuid(_)
                | AppError::Time(_)
                | AppError::Url(_)
        )
    }

    /// Get user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            AppError::WebAuthn(_) => "WebAuthn operation failed".to_string(),
            AppError::Database(_) => "Database operation failed".to_string(),
            AppError::Config(_) => "Server configuration error".to_string(),
            AppError::Validation(msg) => format!("Validation error: {}", msg),
            AppError::Authentication(msg) => format!("Authentication failed: {}", msg),
            AppError::Authorization(msg) => format!("Access denied: {}", msg),
            AppError::NotFound(_) => "Resource not found".to_string(),
            AppError::Conflict(msg) => format!("Conflict: {}", msg),
            AppError::RateLimit => "Rate limit exceeded. Please try again later".to_string(),
            AppError::Jwt(_) => "Invalid authentication token".to_string(),
            AppError::Csrf(_) => "Invalid CSRF token".to_string(),
            AppError::Internal(_) => "Internal server error".to_string(),
            AppError::BadRequest(msg) => format!("Bad request: {}", msg),
            AppError::Timeout => "Request timeout".to_string(),
            AppError::ServiceUnavailable(_) => "Service temporarily unavailable".to_string(),
            AppError::Io(_) => "File system error".to_string(),
            AppError::Json(_) => "Invalid data format".to_string(),
            AppError::Base64(_) => "Invalid base64 data".to_string(),
            AppError::Uuid(_) => "Invalid UUID format".to_string(),
            AppError::Time(_) => "Invalid time format".to_string(),
            AppError::Url(_) => "Invalid URL format".to_string(),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_response = json!({
            "error": {
                "code": status_code.as_u16(),
                "message": self.user_message(),
                "category": self.category(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        });

        HttpResponse::build(status_code).json(error_response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Validation(_) | AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Authentication(_) | AppError::Jwt(_) | AppError::Csrf(_) => {
                StatusCode::UNAUTHORIZED
            }
            AppError::Authorization(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            AppError::Timeout => StatusCode::REQUEST_TIMEOUT,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::WebAuthn(_)
            | AppError::Database(_)
            | AppError::Config(_)
            | AppError::Internal(_)
            | AppError::Io(_)
            | AppError::Json(_)
            | AppError::Base64(_)
            | AppError::Uuid(_)
            | AppError::Time(_)
            | AppError::Url(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// WebAuthn specific errors
#[derive(Error, Debug)]
pub enum WebAuthnError {
    /// Invalid challenge
    #[error("Invalid challenge")]
    InvalidChallenge,

    /// Challenge expired
    #[error("Challenge expired")]
    ChallengeExpired,

    /// Invalid credential
    #[error("Invalid credential")]
    InvalidCredential,

    /// Credential not found
    #[error("Credential not found")]
    CredentialNotFound,

    /// User not found
    #[error("User not found")]
    UserNotFound,

    /// User already exists
    #[error("User already exists")]
    UserAlreadyExists,

    /// Too many credentials
    #[error("Too many credentials for user")]
    TooManyCredentials,

    /// Invalid attestation
    #[error("Invalid attestation")]
    InvalidAttestation,

    /// Invalid assertion
    #[error("Invalid assertion")]
    InvalidAssertion,

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Counter mismatch (possible replay attack)
    #[error("Counter mismatch - possible replay attack")]
    CounterMismatch,

    /// Unsupported algorithm
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,

    /// Invalid origin
    #[error("Invalid origin")]
    InvalidOrigin,

    /// Invalid RP ID
    #[error("Invalid RP ID")]
    InvalidRpId,
}

impl From<WebAuthnError> for AppError {
    fn from(err: WebAuthnError) -> Self {
        match err {
            WebAuthnError::InvalidChallenge
            | WebAuthnError::ChallengeExpired
            | WebAuthnError::InvalidCredential
            | WebAuthnError::InvalidAttestation
            | WebAuthnError::InvalidAssertion
            | WebAuthnError::SignatureVerificationFailed
            | WebAuthnError::CounterMismatch
            | WebAuthnError::UnsupportedAlgorithm
            | WebAuthnError::InvalidOrigin
            | WebAuthnError::InvalidRpId => AppError::Authentication(err.to_string()),
            WebAuthnError::CredentialNotFound | WebAuthnError::UserNotFound => {
                AppError::NotFound(err.to_string())
            }
            WebAuthnError::UserAlreadyExists => AppError::Conflict(err.to_string()),
            WebAuthnError::TooManyCredentials => AppError::BadRequest(err.to_string()),
        }
    }
}

/// Validation errors
#[derive(Error, Debug)]
pub enum ValidationError {
    /// Invalid input format
    #[error("Invalid input format: {field}")]
    InvalidFormat { field: String },

    /// Missing required field
    #[error("Missing required field: {field}")]
    MissingField { field: String },

    /// Invalid length
    #[error("Invalid length for field: {field}")]
    InvalidLength { field: String },

    /// Invalid characters
    #[error("Invalid characters in field: {field}")]
    InvalidCharacters { field: String },

    /// Out of range value
    #[error("Value out of range for field: {field}")]
    OutOfRange { field: String },

    /// Invalid email format
    #[error("Invalid email format")]
    InvalidEmail,

    /// Invalid URL format
    #[error("Invalid URL format")]
    InvalidUrl,

    /// Invalid UUID format
    #[error("Invalid UUID format")]
    InvalidUuid,

    /// Invalid base64 format
    #[error("Invalid base64 format")]
    InvalidBase64,
}

impl From<ValidationError> for AppError {
    fn from(err: ValidationError) -> Self {
        AppError::Validation(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_categories() {
        let err = AppError::Validation("test".to_string());
        assert_eq!(err.category(), "validation");
        assert!(err.is_client_error());
        assert!(!err.is_server_error());
    }

    #[test]
    fn test_webauthn_error_conversion() {
        let err = WebAuthnError::InvalidChallenge;
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::Authentication(_)));
    }

    #[test]
    fn test_error_response() {
        let err = AppError::NotFound("User not found".to_string());
        let response = err.error_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_user_message() {
        let err = AppError::RateLimit;
        assert_eq!(
            err.user_message(),
            "Rate limit exceeded. Please try again later"
        );
    }
}