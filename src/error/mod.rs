use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("User not found: {username}")]
    UserNotFound { username: String },

    #[error("User already exists: {username}")]
    UserAlreadyExists { username: String },

    #[error("Challenge not found or expired")]
    ChallengeNotFound,

    #[error("Invalid credential")]
    InvalidCredential,

    #[error("Origin validation failed: {origin}")]
    InvalidOrigin { origin: String },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Missing required field: {field}")]
    MissingField { field: String },

    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },

    #[error("Internal server error: {message}")]
    Internal { message: String },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status_code, error_message) = match &self {
            AppError::WebAuthn(_) => (StatusCode::BAD_REQUEST, "WebAuthn operation failed"),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error"),
            AppError::Serde(_) => (StatusCode::BAD_REQUEST, "Invalid JSON format"),
            AppError::Validation { .. } => (StatusCode::BAD_REQUEST, &self.to_string()),
            AppError::UserNotFound { .. } => (StatusCode::NOT_FOUND, "User not found"),
            AppError::UserAlreadyExists { .. } => (StatusCode::CONFLICT, "User already exists"),
            AppError::ChallengeNotFound => (StatusCode::BAD_REQUEST, "Invalid or expired challenge"),
            AppError::InvalidCredential => (StatusCode::BAD_REQUEST, "Invalid credential"),
            AppError::InvalidOrigin { .. } => (StatusCode::FORBIDDEN, "Invalid origin"),
            AppError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AppError::MissingField { .. } => (StatusCode::BAD_REQUEST, &self.to_string()),
            AppError::InvalidRequest { .. } => (StatusCode::BAD_REQUEST, &self.to_string()),
            AppError::Internal { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        let error_response = json!({
            "status": "failed",
            "errorMessage": error_message
        });

        tracing::error!("API Error: {} - {}", status_code, self);

        (status_code, Json(error_response)).into_response()
    }
}

impl AppError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}