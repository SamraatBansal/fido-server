use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::WebauthnError),
    
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Connection pool error: {0}")]
    Pool(#[from] r2d2::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Validation error: {message}")]
    Validation { message: String },
    
    #[error("Challenge expired or invalid")]
    ChallengeExpired,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Username already exists")]
    UsernameExists,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Counter regression detected")]
    CounterRegression,
    
    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },
    
    #[error("Internal server error")]
    Internal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }
    
    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, message) = match self {
            AppError::Validation { message } => (actix_web::http::StatusCode::BAD_REQUEST, message.clone()),
            AppError::InvalidRequest { message } => (actix_web::http::StatusCode::BAD_REQUEST, message.clone()),
            AppError::ChallengeExpired => (actix_web::http::StatusCode::BAD_REQUEST, "Challenge expired or invalid".to_string()),
            AppError::UserNotFound => (actix_web::http::StatusCode::NOT_FOUND, "User not found".to_string()),
            AppError::CredentialNotFound => (actix_web::http::StatusCode::NOT_FOUND, "Credential not found".to_string()),
            AppError::UsernameExists => (actix_web::http::StatusCode::CONFLICT, "Username already exists".to_string()),
            AppError::InvalidSignature => (actix_web::http::StatusCode::BAD_REQUEST, "Invalid signature".to_string()),
            AppError::CounterRegression => (actix_web::http::StatusCode::BAD_REQUEST, "Counter regression detected".to_string()),
            AppError::WebAuthn(e) => (actix_web::http::StatusCode::BAD_REQUEST, format!("WebAuthn error: {}", e)),
            _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };
        
        HttpResponse::build(status_code).json(ServerResponse::error(&message))
    }
    
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AppError::Validation { .. } | AppError::InvalidRequest { .. } | AppError::ChallengeExpired 
            | AppError::InvalidSignature | AppError::CounterRegression | AppError::WebAuthn(_) => {
                actix_web::http::StatusCode::BAD_REQUEST
            }
            AppError::UserNotFound | AppError::CredentialNotFound => {
                actix_web::http::StatusCode::NOT_FOUND
            }
            AppError::UsernameExists => {
                actix_web::http::StatusCode::CONFLICT
            }
            _ => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}