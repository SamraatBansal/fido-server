//! Error type definitions

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;
use webauthn_rs::error::WebauthnError;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebauthnError),

    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[error("Database connection error: {0}")]
    DatabaseConnection(String),

    #[error("Invalid credential: {0}")]
    InvalidCredential(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Session expired")]
    SessionExpired,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Invalid session: {0}")]
    InvalidSession(String),

    #[error("Invalid session state")]
    InvalidSessionState,

    #[error("Too many sessions")]
    TooManySessions(String),

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),

    #[error("Invalid encryption: {0}")]
    InvalidEncryption(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Replay attack detected")]
    ReplayAttack,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        use crate::schema::responses::ErrorResponse;

        let (status_code, error_type, message) = match self {
            AppError::WebAuthn(e) => {
                log::error!("WebAuthn error: {:?}", e);
                (actix_web::http::StatusCode::BAD_REQUEST, "webauthn_error", "WebAuthn operation failed")
            },
            AppError::InvalidCredential(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, "invalid_credential", msg)
            },
            AppError::AuthenticationFailed(msg) => {
                (actix_web::http::StatusCode::UNAUTHORIZED, "authentication_failed", msg)
            },
            AppError::AuthorizationFailed(msg) => {
                (actix_web::http::StatusCode::FORBIDDEN, "authorization_failed", msg)
            },
            AppError::RateLimitExceeded => {
                (actix_web::http::StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded", "Rate limit exceeded")
            },
            AppError::SessionExpired => {
                (actix_web::http::StatusCode::UNAUTHORIZED, "session_expired", "Session has expired")
            },
            AppError::SessionNotFound => {
                (actix_web::http::StatusCode::NOT_FOUND, "session_not_found", "Session not found")
            },
            AppError::InvalidRequest(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, "invalid_request", msg)
            },
            AppError::Database(e) => {
                log::error!("Database error: {:?}", e);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database operation failed")
            },
            AppError::DatabaseConnection(e) => {
                log::error!("Database connection error: {}", e);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "database_connection_error", "Database connection failed")
            },
            AppError::Configuration(msg) => {
                log::error!("Configuration error: {}", msg);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "configuration_error", "Server configuration error")
            },
            AppError::Serialization(e) => {
                log::error!("Serialization error: {:?}", e);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "serialization_error", "Data serialization failed")
            },
            AppError::Uuid(e) => {
                log::error!("UUID error: {:?}", e);
                (actix_web::http::StatusCode::BAD_REQUEST, "uuid_error", "Invalid UUID format")
            },
            AppError::Url(e) => {
                log::error!("URL error: {:?}", e);
                (actix_web::http::StatusCode::BAD_REQUEST, "url_error", "Invalid URL format")
            },
            AppError::Base64(e) => {
                log::error!("Base64 error: {:?}", e);
                (actix_web::http::StatusCode::BAD_REQUEST, "base64_error", "Invalid base64 format")
            },
            AppError::Io(e) => {
                log::error!("IO error: {:?}", e);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "io_error", "IO operation failed")
            },
            AppError::Internal(msg) => {
                log::error!("Internal error: {}", msg);
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "Internal server error")
            },
            AppError::InvalidSession(msg) => {
                (actix_web::http::StatusCode::UNAUTHORIZED, "invalid_session", msg)
            },
            AppError::TooManySessions(msg) => {
                (actix_web::http::StatusCode::TOO_MANY_REQUESTS, "too_many_sessions", msg)
            },
            AppError::InvalidToken(msg) => {
                (actix_web::http::StatusCode::UNAUTHORIZED, "invalid_token", msg)
            },
            AppError::InvalidAttestation(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, "invalid_attestation", msg)
            },
            AppError::InvalidEncryption(msg) => {
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "invalid_encryption", msg)
            },
            AppError::InvalidPassword(msg) => {
                (actix_web::http::StatusCode::BAD_REQUEST, "invalid_password", msg)
            },
            AppError::ReplayAttack => {
                log::error!("Replay attack detected");
                (actix_web::http::StatusCode::FORBIDDEN, "replay_attack", "Replay attack detected")
            },
        };

        let error_response = ErrorResponse::new(error_type, message);

        HttpResponse::build(status_code).json(error_response)
    }
}