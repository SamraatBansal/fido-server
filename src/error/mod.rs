//! Error types for the FIDO Server

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),
    
    #[error("Invalid assertion: {0}")]
    InvalidAssertion(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            AppError::InvalidInput(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::UserNotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            AppError::CredentialNotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            AppError::InvalidChallenge(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::InvalidSignature(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::InvalidAttestation(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::InvalidAssertion(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::Database(_) | AppError::DatabaseConnection(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::WebAuthn(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::Serialization(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        HttpResponse::build(status).json(ServerResponse {
            status: "failed".to_string(),
            error_message: self.to_string(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }
}