//! Error handling for FIDO2/WebAuthn server

use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;

/// Custom error types for WebAuthn operations
#[derive(Debug)]
pub enum WebAuthnError {
    /// Configuration errors
    Configuration(String),
    /// WebAuthn library errors  
    WebAuthn(webauthn_rs::WebauthnError),
    /// Storage errors
    Storage(String),
    /// Validation errors
    Validation(String),
    /// Authentication/Registration failures
    AuthenticationFailed(String),
    /// Challenge not found or expired
    ChallengeNotFound,
    /// User not found
    UserNotFound,
    /// Credential not found
    CredentialNotFound,
    /// Invalid input data
    InvalidInput(String),
    /// Serialization errors
    Serialization(String),
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebAuthnError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            WebAuthnError::WebAuthn(err) => write!(f, "WebAuthn error: {}", err),
            WebAuthnError::Storage(msg) => write!(f, "Storage error: {}", msg),
            WebAuthnError::Validation(msg) => write!(f, "Validation error: {}", msg),
            WebAuthnError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            WebAuthnError::ChallengeNotFound => write!(f, "Challenge not found or expired"),
            WebAuthnError::UserNotFound => write!(f, "User not found"),
            WebAuthnError::CredentialNotFound => write!(f, "Credential not found"),
            WebAuthnError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            WebAuthnError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for WebAuthnError {}

impl From<webauthn_rs::WebauthnError> for WebAuthnError {
    fn from(err: webauthn_rs::WebauthnError) -> Self {
        WebAuthnError::WebAuthn(err)
    }
}

impl From<serde_json::Error> for WebAuthnError {
    fn from(err: serde_json::Error) -> Self {
        WebAuthnError::Serialization(err.to_string())
    }
}

impl ResponseError for WebAuthnError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, error_message) = match self {
            WebAuthnError::Configuration(_) => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error"
            ),
            WebAuthnError::WebAuthn(_) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "WebAuthn operation failed"
            ),
            WebAuthnError::Storage(_) => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error"
            ),
            WebAuthnError::Validation(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                msg
            ),
            WebAuthnError::AuthenticationFailed(msg) => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                msg
            ),
            WebAuthnError::ChallengeNotFound => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "Challenge not found or expired"
            ),
            WebAuthnError::UserNotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "User not found"
            ),
            WebAuthnError::CredentialNotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "Credential not found"
            ),
            WebAuthnError::InvalidInput(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                msg
            ),
            WebAuthnError::Serialization(_) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "Invalid request format"
            ),
        };

        HttpResponse::build(status_code).json(json!({
            "status": "failed",
            "errorMessage": error_message
        }))
    }
}