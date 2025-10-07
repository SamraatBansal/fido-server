use actix_web::{error::ResponseError, HttpResponse};
use diesel::result::Error as DieselError;
use thiserror::Error;
use webauthn_rs::prelude::WebauthnError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] DieselError),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebauthnError),
    
    #[error("Connection pool error: {0}")]
    ConnectionPool(#[from] r2d2::Error),
    
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("User verification failed")]
    UserVerificationFailed,
    
    #[error("Attestation verification failed: {0}")]
    AttestationVerificationFailed(String),
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Session not found")]
    SessionNotFound,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Invalid request format: {0}")]
    InvalidRequest(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Database(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "database_error",
                    "message": "Internal database error"
                }))
            }
            AppError::WebAuthn(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "webauthn_error",
                    "message": "WebAuthn processing error"
                }))
            }
            AppError::ConnectionPool(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "connection_pool_error",
                    "message": "Database connection pool error"
                }))
            }
            AppError::InvalidChallenge(_) | AppError::InvalidSignature | 
            AppError::UserVerificationFailed | AppError::AttestationVerificationFailed(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "authentication_error",
                    "message": self.to_string()
                }))
            }
            AppError::CredentialNotFound | AppError::UserNotFound | AppError::SessionNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "not_found",
                    "message": self.to_string()
                }))
            }
            AppError::SessionExpired => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "session_expired",
                    "message": "Authentication session has expired"
                }))
            }
            AppError::RateLimitExceeded => {
                HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests, please try again later"
                }))
            }
            AppError::InvalidRequest(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_request",
                    "message": self.to_string()
                }))
            }
            AppError::Serialization(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "serialization_error",
                    "message": "Data serialization error"
                }))
            }
            AppError::Configuration(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "configuration_error",
                    "message": "Server configuration error"
                }))
            }
            AppError::Internal(_) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "message": "Internal server error"
                }))
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;