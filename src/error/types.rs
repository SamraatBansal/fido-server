//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde_json::json;
use std::fmt;
use thiserror::Error;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types following FIDO2 specification
#[derive(Debug, Error)]
pub enum AppError {
    /// Database connection or query error
    #[error("Database connection failed")]
    DatabaseError(String),
    
    /// Redis connection or operation error
    #[error("Redis connection failed")]
    RedisError(String),
    
    /// Configuration error
    #[error("Configuration error")]
    ConfigError(String),
    
    /// WebAuthn protocol error
    #[error("WebAuthn operation failed")]
    WebAuthnError(String),
    
    /// Input validation error
    #[error("Invalid input")]
    ValidationError(String),
    
    /// Resource not found error
    #[error("Resource not found")]
    NotFound(String),
    
    /// Internal server error
    #[error("Internal server error")]
    InternalError(String),
    
    /// Bad request error
    #[error("Bad request")]
    BadRequest(String),
    
    /// Service unavailable
    #[error("Service unavailable")]
    ServiceUnavailable(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = match self {
            // Hide detailed internal errors for security
            Self::DatabaseError(_) => "Database connection failed".to_string(),
            Self::RedisError(_) => "Redis connection failed".to_string(),
            Self::ConfigError(_) => "Configuration error".to_string(),
            Self::InternalError(_) => "Internal server error".to_string(),
            // Show user-facing errors
            Self::WebAuthnError(msg) => msg.clone(),
            Self::ValidationError(msg) => msg.clone(),
            Self::NotFound(msg) => msg.clone(),
            Self::BadRequest(msg) => msg.clone(),
            Self::ServiceUnavailable(msg) => msg.clone(),
        };

        // FIDO2 compliant error format
        HttpResponse::build(status_code)
            .content_type("application/json")
            .json(json!({
                "status": "error",
                "errorMessage": error_message
            }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseError(_) | Self::RedisError(_) | Self::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::WebAuthnError(_) | Self::ValidationError(_) | Self::BadRequest(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

// Conversion implementations for external error types
impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        log::error!("Configuration error: {}", err);
        Self::ConfigError("Configuration loading failed".to_string())
    }
}

impl From<r2d2::Error> for AppError {
    fn from(err: r2d2::Error) -> Self {
        log::error!("Database pool error: {}", err);
        Self::DatabaseError("Database connection failed".to_string())
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        log::error!("Database operation error: {}", err);
        match err {
            diesel::result::Error::NotFound => Self::NotFound("Resource not found".to_string()),
            _ => Self::DatabaseError("Database operation failed".to_string()),
        }
    }
}

impl From<deadpool_redis::PoolError> for AppError {
    fn from(err: deadpool_redis::PoolError) -> Self {
        log::error!("Redis pool error: {}", err);
        Self::RedisError("Redis connection failed".to_string())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        log::error!("Redis operation error: {}", err);
        Self::RedisError("Redis operation failed".to_string())
    }
}
