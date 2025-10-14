use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, FidoError>;

#[derive(Error, Debug)]
pub enum FidoError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Challenge not found or expired")]
    ChallengeNotFound,

    #[error("Challenge already used")]
    ChallengeAlreadyUsed,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Registration failed: {0}")]
    RegistrationFailed(String),

    #[error("Invalid origin: expected {expected}, got {actual}")]
    InvalidOrigin { expected: String, actual: String },

    #[error("Invalid RP ID: expected {expected}, got {actual}")]
    InvalidRpId { expected: String, actual: String },

    #[error("Counter rollback detected: stored {stored}, received {received}")]
    CounterRollback { stored: u32, received: u32 },

    #[error("Too many credentials for user: {username} (max: {max})")]
    TooManyCredentials { username: String, max: usize },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Configuration error: {0}")]
    Configuration(String),
}

impl IntoResponse for FidoError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match &self {
            FidoError::WebAuthn(_) => (
                StatusCode::BAD_REQUEST,
                "WebAuthn operation failed",
                "WEBAUTHN_ERROR",
            ),
            FidoError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database operation failed",
                "DATABASE_ERROR",
            ),
            FidoError::InvalidRequest(_) => (
                StatusCode::BAD_REQUEST,
                "Invalid request format",
                "INVALID_REQUEST",
            ),
            FidoError::UserNotFound(_) => (
                StatusCode::NOT_FOUND,
                "User not found",
                "USER_NOT_FOUND",
            ),
            FidoError::CredentialNotFound(_) => (
                StatusCode::NOT_FOUND,
                "Credential not found",
                "CREDENTIAL_NOT_FOUND",
            ),
            FidoError::ChallengeNotFound => (
                StatusCode::BAD_REQUEST,
                "Challenge not found or expired",
                "CHALLENGE_NOT_FOUND",
            ),
            FidoError::ChallengeAlreadyUsed => (
                StatusCode::BAD_REQUEST,
                "Challenge already used",
                "CHALLENGE_ALREADY_USED",
            ),
            FidoError::AuthenticationFailed(_) => (
                StatusCode::UNAUTHORIZED,
                "Authentication failed",
                "AUTHENTICATION_FAILED",
            ),
            FidoError::RegistrationFailed(_) => (
                StatusCode::BAD_REQUEST,
                "Registration failed",
                "REGISTRATION_FAILED",
            ),
            FidoError::InvalidOrigin { .. } => (
                StatusCode::BAD_REQUEST,
                "Invalid origin",
                "INVALID_ORIGIN",
            ),
            FidoError::InvalidRpId { .. } => (
                StatusCode::BAD_REQUEST,
                "Invalid RP ID",
                "INVALID_RP_ID",
            ),
            FidoError::CounterRollback { .. } => (
                StatusCode::BAD_REQUEST,
                "Counter rollback detected",
                "COUNTER_ROLLBACK",
            ),
            FidoError::TooManyCredentials { .. } => (
                StatusCode::BAD_REQUEST,
                "Too many credentials",
                "TOO_MANY_CREDENTIALS",
            ),
            FidoError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                "RATE_LIMIT_EXCEEDED",
            ),
            FidoError::Configuration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration error",
                "CONFIGURATION_ERROR",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "INTERNAL_ERROR",
            ),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": error_message,
                "details": format!("{}", self),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        }));

        (status, body).into_response()
    }
}

// Helper function to create internal errors
impl FidoError {
    pub fn internal<T: std::fmt::Display>(msg: T) -> Self {
        FidoError::Internal(msg.to_string())
    }

    pub fn invalid_request<T: std::fmt::Display>(msg: T) -> Self {
        FidoError::InvalidRequest(msg.to_string())
    }

    pub fn authentication_failed<T: std::fmt::Display>(msg: T) -> Self {
        FidoError::AuthenticationFailed(msg.to_string())
    }

    pub fn registration_failed<T: std::fmt::Display>(msg: T) -> Self {
        FidoError::RegistrationFailed(msg.to_string())
    }

    pub fn configuration<T: std::fmt::Display>(msg: T) -> Self {
        FidoError::Configuration(msg.to_string())
    }
}