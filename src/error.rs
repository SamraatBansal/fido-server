use actix_web::{HttpResponse, ResponseError};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Challenge expired or invalid")]
    ChallengeExpired,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Missing field: {0}")]
    MissingField(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("Attestation verification failed: {0}")]
    AttestationFailed(String),
    
    #[error("Internal server error")]
    InternalServerError,
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
}

impl ErrorResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
            timestamp: Some(Utc::now()),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, error_message) = match self {
            Self::ValidationError(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                msg.clone()
            ),
            Self::InvalidInput(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                msg.clone()
            ),
            Self::MissingField(field) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Missing required field: {}", field)
            ),
            Self::InvalidFormat(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                msg.clone()
            ),
            Self::ChallengeExpired => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "Challenge has expired or is invalid".to_string()
            ),
            Self::UserNotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "User not found".to_string()
            ),
            Self::CredentialNotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "Credential not found".to_string()
            ),
            Self::AuthenticationFailed => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "Authentication failed".to_string()
            ),
            Self::RegistrationFailed(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Registration failed: {}", msg)
            ),
            Self::AttestationFailed(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Attestation verification failed: {}", msg)
            ),
            Self::WebAuthnError(err) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("WebAuthn error: {}", err)
            ),
            Self::DatabaseError(_) => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Database error occurred".to_string()
            ),
            _ => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string()
            ),
        };

        HttpResponse::build(status_code).json(ErrorResponse::new(error_message))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;