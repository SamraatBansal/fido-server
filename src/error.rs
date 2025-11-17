use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    WebAuthn(String),
    Serialization(serde_json::Error),
    Base64Decode(base64::DecodeError),
    InvalidInput(String),
    NotFound(String),
    Unauthorized(String),
    ChallengeExpired,
    ChallengeNotFound,
    UserNotFound,
    CredentialNotFound,
    InvalidSignature,
    CounterRegression,
    InvalidOrigin,
    InvalidChallenge,
    DuplicateCredential,
    InvalidCredentialId,
    AttestationVerificationFailed,
    AssertionVerificationFailed,
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::WebAuthn(e) => write!(f, "WebAuthn error: {}", e),
            AppError::Serialization(e) => write!(f, "Serialization error: {}", e),
            AppError::Base64Decode(e) => write!(f, "Base64 decode error: {}", e),
            AppError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::ChallengeExpired => write!(f, "Challenge expired"),
            AppError::ChallengeNotFound => write!(f, "Challenge not found"),
            AppError::UserNotFound => write!(f, "User not found"),
            AppError::CredentialNotFound => write!(f, "Credential not found"),
            AppError::InvalidSignature => write!(f, "Invalid signature"),
            AppError::CounterRegression => write!(f, "Counter regression detected"),
            AppError::InvalidOrigin => write!(f, "Invalid origin"),
            AppError::InvalidChallenge => write!(f, "Invalid challenge"),
            AppError::DuplicateCredential => write!(f, "Duplicate credential"),
            AppError::InvalidCredentialId => write!(f, "Invalid credential ID"),
            AppError::AttestationVerificationFailed => write!(f, "Attestation verification failed"),
            AppError::AssertionVerificationFailed => write!(f, "Assertion verification failed"),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Database(err)
    }
}

impl From<webauthn_rs::error::WebauthnError> for AppError {
    fn from(err: webauthn_rs::error::WebauthnError) -> Self {
        AppError::WebAuthn(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Serialization(err)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        AppError::Base64Decode(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
            AppError::WebAuthn(_) => (StatusCode::BAD_REQUEST, "WebAuthn processing failed".to_string()),
            AppError::Serialization(_) => (StatusCode::BAD_REQUEST, "Invalid request format".to_string()),
            AppError::Base64Decode(_) => (StatusCode::BAD_REQUEST, "Invalid base64 encoding".to_string()),
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::ChallengeExpired => (StatusCode::BAD_REQUEST, "Challenge expired".to_string()),
            AppError::ChallengeNotFound => (StatusCode::BAD_REQUEST, "Challenge not found".to_string()),
            AppError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            AppError::CredentialNotFound => (StatusCode::NOT_FOUND, "Credential not found".to_string()),
            AppError::InvalidSignature => (StatusCode::BAD_REQUEST, "Can not validate response signature!".to_string()),
            AppError::CounterRegression => (StatusCode::BAD_REQUEST, "Counter regression detected".to_string()),
            AppError::InvalidOrigin => (StatusCode::BAD_REQUEST, "Invalid origin".to_string()),
            AppError::InvalidChallenge => (StatusCode::BAD_REQUEST, "Invalid challenge".to_string()),
            AppError::DuplicateCredential => (StatusCode::CONFLICT, "Credential already exists".to_string()),
            AppError::InvalidCredentialId => (StatusCode::BAD_REQUEST, "Invalid credential ID".to_string()),
            AppError::AttestationVerificationFailed => (StatusCode::BAD_REQUEST, "Can not validate response signature!".to_string()),
            AppError::AssertionVerificationFailed => (StatusCode::BAD_REQUEST, "Can not validate response signature!".to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        tracing::error!("AppError: {}", self);

        let body = Json(json!({
            "status": "failed",
            "errorMessage": error_message
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;