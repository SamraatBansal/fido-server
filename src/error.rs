use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Mapping not found")]
    MappingNotFound,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Database(ref e) => {
                tracing::error!("Database error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::WebAuthn(ref e) => {
                tracing::error!("WebAuthn error: {}", e);
                (StatusCode::BAD_REQUEST, "WebAuthn operation failed")
            }
            AppError::InvalidRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::AuthenticationFailed => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            AppError::CredentialNotFound => (StatusCode::NOT_FOUND, "Credential not found"),
            AppError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AppError::MappingNotFound => (StatusCode::NOT_FOUND, "Mapping not found"),
            AppError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AppError::Serialization(ref e) => {
                tracing::error!("Serialization error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::Internal(ref msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;