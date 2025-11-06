//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use diesel::r2d2;
use std::fmt;

use crate::dto::ServerResponse;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Debug)]
pub enum AppError {
    /// Database error
    DatabaseError(String),
    /// WebAuthn error
    WebAuthnError(String),
    /// Validation error
    ValidationError(String),
    /// Not found error
    NotFound(String),
    /// Internal server error
    InternalError(String),
    /// Bad request error
    BadRequest(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            Self::WebAuthnError(msg) => write!(f, "WebAuthn error: {msg}"),
            Self::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            Self::NotFound(msg) => write!(f, "Not found: {msg}"),
            Self::InternalError(msg) => write!(f, "Internal error: {msg}"),
            Self::BadRequest(msg) => write!(f, "Bad request: {msg}"),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let server_response = ServerResponse::failed(&self.to_string());

        HttpResponse::build(status_code).json(server_response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseError(_) | Self::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthnError(_) => StatusCode::BAD_REQUEST,
            Self::ValidationError(_) | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

impl std::error::Error for AppError {}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

impl From<r2d2::PoolError> for AppError {
    fn from(err: r2d2::PoolError) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

impl From<webauthn_rs::prelude::WebauthnError> for AppError {
    fn from(err: webauthn_rs::prelude::WebauthnError) -> Self {
        Self::WebAuthnError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::InternalError(format!("JSON error: {}", err))
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        Self::ValidationError(format!("Base64 decode error: {}", err))
    }
}

impl From<url::ParseError> for AppError {
    fn from(err: url::ParseError) -> Self {
        Self::ValidationError(format!("URL parse error: {}", err))
    }
}
