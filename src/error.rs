use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),

    #[error("WebAuthn error: {0}")]
    WebAuthnError(#[from] webauthn_rs::WebauthnError),

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

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Missing field: {0}")]
    MissingField(String),

    #[error("Invalid field: {0}")]
    InvalidField(String),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Connection pool error: {0}")]
    PoolError(#[from] r2d2::Error),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, error_message) = match self {
            Self::ValidationError(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg.clone()),
            Self::ChallengeExpired => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "Challenge has expired or is invalid".to_string(),
            ),
            Self::UserNotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "User not found".to_string(),
            ),
            Self::CredentialNotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "Credential not found".to_string(),
            ),
            Self::AuthenticationFailed => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "Authentication failed".to_string(),
            ),
            Self::RegistrationFailed(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Registration failed: {}", msg),
            ),
            Self::InvalidRequest(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Invalid request: {}", msg),
            ),
            Self::MissingField(field) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Missing required field: {}", field),
            ),
            Self::InvalidField(field) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                format!("Invalid field: {}", field),
            ),
            Self::WebAuthnError(_) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "WebAuthn validation failed".to_string(),
            ),
            _ => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        HttpResponse::build(status_code).json(json!({
            "status": "failed",
            "errorMessage": error_message
        }))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

// Validation helpers
pub fn validate_required_field<T>(field: &Option<T>, field_name: &str) -> Result<()> {
    if field.is_none() {
        return Err(AppError::MissingField(field_name.to_string()));
    }
    Ok(())
}

pub fn validate_string_not_empty(value: &str, field_name: &str) -> Result<()> {
    if value.is_empty() {
        return Err(AppError::InvalidField(format!("{} cannot be empty", field_name)));
    }
    Ok(())
}

pub fn validate_base64url(value: &str, field_name: &str) -> Result<Vec<u8>> {
    base64::decode_config(value, base64::URL_SAFE_NO_PAD)
        .map_err(|_| AppError::InvalidField(format!("{} is not valid base64url", field_name)))
}

pub fn validate_credential_type(type_: &str) -> Result<()> {
    if type_ != "public-key" {
        return Err(AppError::InvalidField(format!(
            "Invalid credential type: {}. Expected 'public-key'", 
            type_
        )));
    }
    Ok(())
}

pub fn validate_challenge_length(challenge: &[u8]) -> Result<()> {
    if challenge.len() < 16 {
        return Err(AppError::ValidationError(
            "Challenge must be at least 16 bytes".to_string(),
        ));
    }
    if challenge.len() > 64 {
        return Err(AppError::ValidationError(
            "Challenge must be at most 64 bytes".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_user_id_length(user_id: &[u8]) -> Result<()> {
    if user_id.is_empty() {
        return Err(AppError::ValidationError(
            "User ID cannot be empty".to_string(),
        ));
    }
    if user_id.len() > 64 {
        return Err(AppError::ValidationError(
            "User ID must be at most 64 bytes".to_string(),
        ));
    }
    Ok(())
}