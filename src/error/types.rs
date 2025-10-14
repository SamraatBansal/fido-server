use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Challenge expired or invalid")]
    InvalidChallenge,
    
    #[error("Invalid request: {0}")]
    BadRequest(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
            details: None,
        }
    }

    pub fn with_details(message: impl Into<String>, details: serde_json::Value) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
            details: Some(details),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse::new(self.to_string());
        
        match self {
            AppError::UserNotFound => HttpResponse::NotFound().json(error_response),
            AppError::CredentialNotFound => HttpResponse::NotFound().json(error_response),
            AppError::Validation(_) => HttpResponse::BadRequest().json(error_response),
            AppError::BadRequest(_) => HttpResponse::BadRequest().json(error_response),
            AppError::InvalidChallenge => HttpResponse::BadRequest().json(error_response),
            AppError::Authentication(_) => HttpResponse::Unauthorized().json(error_response),
            AppError::WebAuthn(webauthn_err) => {
                log::error!("WebAuthn error: {:?}", webauthn_err);
                HttpResponse::BadRequest().json(ErrorResponse::new("WebAuthn validation failed"))
            }
            AppError::Database(db_err) => {
                log::error!("Database error: {:?}", db_err);
                HttpResponse::InternalServerError().json(ErrorResponse::new("Internal server error"))
            }
            _ => {
                log::error!("Internal error: {:?}", self);
                HttpResponse::InternalServerError().json(ErrorResponse::new("Internal server error"))
            }
        }
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.status, self.error_message)
    }
}