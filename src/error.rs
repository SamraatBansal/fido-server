use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::prelude::WebauthnError),
    
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),
    
    #[error("Validation error: {message}")]
    Validation { message: String },
    
    #[error("User not found: {username}")]
    UserNotFound { username: String },
    
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Missing required field: {field}")]
    MissingField { field: String },
    
    #[error("Internal server error: {message}")]
    Internal { message: String },
    
    #[error("Configuration error: {0}")]
    Config(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status_code, error_message) = match &self {
            AppError::WebAuthn(_) => (StatusCode::BAD_REQUEST, "WebAuthn operation failed"),
            AppError::Serde(_) => (StatusCode::BAD_REQUEST, "Invalid JSON format"),
            AppError::Validation { message } => (StatusCode::BAD_REQUEST, message.as_str()),
            AppError::UserNotFound { .. } => (StatusCode::NOT_FOUND, "User not found"),
            AppError::ChallengeNotFound => (StatusCode::BAD_REQUEST, "Invalid or expired challenge"),
            AppError::CredentialNotFound => (StatusCode::NOT_FOUND, "Credential not found"),
            AppError::MissingField { field } => (StatusCode::BAD_REQUEST, "Missing required field"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        let error_response = json!({
            "status": "failed",
            "errorMessage": error_message
        });

        tracing::error!("API Error: {} - {}", status_code, self);
        (status_code, Json(error_response)).into_response()
    }
}