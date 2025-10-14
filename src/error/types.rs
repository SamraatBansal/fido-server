//! Error types for the FIDO server

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;

use thiserror::Error;

/// Application error type
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Internal server error: {0}")]
    InternalServerError(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::WebauthnError),
    
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl AppError {
    pub fn bad_request<T: Into<String>>(msg: T) -> Self {
        Self::BadRequest(msg.into())
    }
    
    pub fn unauthorized<T: Into<String>>(msg: T) -> Self {
        Self::Unauthorized(msg.into())
    }
    
    pub fn forbidden<T: Into<String>>(msg: T) -> Self {
        Self::Forbidden(msg.into())
    }
    
    pub fn not_found<T: Into<String>>(msg: T) -> Self {
        Self::NotFound(msg.into())
    }
    
    pub fn conflict<T: Into<String>>(msg: T) -> Self {
        Self::Conflict(msg.into())
    }
    
    pub fn internal_server_error<T: Into<String>>(msg: T) -> Self {
        Self::InternalServerError(msg.into())
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let message = self.to_string();
        
        HttpResponse::build(status).json(json!({
            "status": "failed",
            "errorMessage": message
        }))
    }
    
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::WebAuthn(_) => StatusCode::BAD_REQUEST,
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseConnection(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Serialization(_) => StatusCode::BAD_REQUEST,
            Self::Base64Decode(_) => StatusCode::BAD_REQUEST,
            Self::Utf8(_) => StatusCode::BAD_REQUEST,
        }
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, AppError>;