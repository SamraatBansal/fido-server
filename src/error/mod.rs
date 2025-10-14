//! Error handling for the FIDO2/WebAuthn server

use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::ConnectionError),

    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Invalid challenge")]
    InvalidChallenge,

    #[error("User not found")]
    UserNotFound,

    #[error("Credential not found")]
    CredentialNotFound,

    #[error("Duplicate credential")]
    DuplicateCredential,

    #[error("Replay attack detected: {0}")]
    ReplayAttack(String),

    #[error("Attestation verification failed: {0}")]
    AttestationVerificationFailed(String),

    #[error("Assertion verification failed: {0}")]
    AssertionVerificationFailed(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Base64 encoding error: {0}")]
    Base64Encoding(#[from] base64::DecodeError),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::InvalidInput(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::ChallengeExpired => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Challenge has expired"
                }))
            }
            AppError::InvalidChallenge => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Invalid challenge"
                }))
            }
            AppError::UserNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "User does not exist!"
                }))
            }
            AppError::CredentialNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Credential not found"
                }))
            }
            AppError::DuplicateCredential => {
                HttpResponse::Conflict().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Credential already exists"
                }))
            }
            AppError::ReplayAttack(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": format!("Replay attack detected: {}", msg)
                }))
            }
            AppError::AttestationVerificationFailed(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": format!("Attestation verification failed: {}", msg)
                }))
            }
            AppError::AssertionVerificationFailed(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": format!("Can not validate response signature! {}", msg)
                }))
            }
            AppError::WebAuthn(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": format!("WebAuthn error: {}", msg)
                }))
            }
            _ => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Internal server error"
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_invalid_input_error_response() {
        let error = AppError::InvalidInput("test error".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_user_not_found_error_response() {
        let error = AppError::UserNotFound;
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_replay_attack_error_response() {
        let error = AppError::ReplayAttack("test replay".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_internal_error_response() {
        let error = AppError::Internal("test internal".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}