//! Error handling for FIDO Server

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;
use webauthn_rs_core::error::WebauthnError;

/// Application error type
#[derive(Error, Debug)]
pub enum AppError {
    /// Database errors
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    /// Database connection errors
    #[error("Database connection error: {0}")]
    DatabaseConnection(String),

    /// WebAuthn errors
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebauthnError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Not found errors
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Unauthorized errors
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Rate limit errors
    #[error("Rate limit exceeded")]
    RateLimit,

    /// Internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// UUID parsing errors
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    /// Base64 decoding errors
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Challenge errors
    #[error("Challenge error: {0}")]
    Challenge(String),

    /// Credential errors
    #[error("Credential error: {0}")]
    Credential(String),

    /// User errors
    #[error("User error: {0}")]
    User(String),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Database(_) | AppError::DatabaseConnection(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "database_error",
                    "message": "A database error occurred"
                }))
            }
            AppError::WebAuthn(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "webauthn_error",
                    "message": "WebAuthn operation failed"
                }))
            }
            AppError::Validation(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "validation_error",
                    "message": msg
                }))
            }
            AppError::Authentication(msg) => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "authentication_error",
                    "message": msg
                }))
            }
            AppError::NotFound(msg) => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "not_found",
                    "message": msg
                }))
            }
            AppError::Unauthorized(msg) => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "unauthorized",
                    "message": msg
                }))
            }
            AppError::RateLimit => {
                HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error": "rate_limit_exceeded",
                    "message": "Rate limit exceeded. Please try again later."
                }))
            }
            AppError::Challenge(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "challenge_error",
                    "message": msg
                }))
            }
            AppError::Credential(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "credential_error",
                    "message": msg
                }))
            }
            AppError::User(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "user_error",
                    "message": msg
                }))
            }
            AppError::Config(msg) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "configuration_error",
                    "message": format!("Configuration error: {}", msg)
                }))
            }
            AppError::Internal(msg) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "message": "An internal server error occurred"
                }))
            }
            AppError::Serialization(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "serialization_error",
                    "message": "Invalid JSON format"
                }))
            }
            AppError::Uuid(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "uuid_error",
                    "message": "Invalid UUID format"
                }))
            }
            AppError::Base64(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "base64_error",
                    "message": "Invalid base64 format"
                }))
            }
            AppError::Io(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "io_error",
                    "message": "An IO error occurred"
                }))
            }
        }
    }
}

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;