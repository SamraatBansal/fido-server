//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::Serialize;
use std::fmt;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Debug)]
pub enum AppError {
    /// Database error
    DatabaseError(String),
    /// Redis error
    RedisError(String),
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
    /// Configuration error
    ConfigError(String),
    /// Service unavailable error
    ServiceUnavailable(String),
}

/// Standard JSON error response format
#[derive(Serialize)]
struct ErrorResponse {
    status: String,
    #[serde(rename = "errorMessage")]
    error_message: String,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseError(_) => write!(f, "Database connection failed"),
            Self::RedisError(_) => write!(f, "Redis connection failed"),
            Self::WebAuthnError(msg) => write!(f, "Authentication error: {msg}"),
            Self::ValidationError(msg) => write!(f, "Validation failed: {msg}"),
            Self::NotFound(msg) => write!(f, "Resource not found: {msg}"),
            Self::InternalError(_) => write!(f, "Internal server error"),
            Self::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            Self::ConfigError(_) => write!(f, "Configuration error"),
            Self::ServiceUnavailable(msg) => write!(f, "Service unavailable - {msg}"),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = self.to_string();
        
        // Log the actual error details for debugging (but don't expose them)
        match self {
            Self::DatabaseError(details) => log::error!("Database error: {}", details),
            Self::RedisError(details) => log::error!("Redis error: {}", details),
            Self::InternalError(details) => log::error!("Internal error: {}", details),
            Self::ConfigError(details) => log::error!("Config error: {}", details),
            _ => {},
        }
        
        let response = ErrorResponse {
            status: "error".to_string(),
            error_message,
        };

        HttpResponse::build(status_code).json(response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseError(_) | Self::RedisError(_) | Self::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthnError(_) => StatusCode::BAD_REQUEST,
            Self::ValidationError(_) | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl std::error::Error for AppError {}

// Conversion implementations for common error types
impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        Self::DatabaseError(format!("{:?}", err))
    }
}

impl From<r2d2::Error> for AppError {
    fn from(err: r2d2::Error) -> Self {
        Self::DatabaseError(format!("{:?}", err))
    }
}

impl From<deadpool_redis::PoolError> for AppError {
    fn from(err: deadpool_redis::PoolError) -> Self {
        Self::RedisError(format!("{:?}", err))
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        Self::RedisError(format!("{:?}", err))
    }
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        Self::ConfigError(format!("{:?}", err))
    }
}
