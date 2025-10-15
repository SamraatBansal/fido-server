use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    #[error("Invalid attestation")]
    InvalidAttestation,
    
    #[error("Invalid assertion")]
    InvalidAssertion,
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse {
            status: "failed".to_string(),
            error_message: self.to_string(),
        };

        match self {
            AppError::InvalidRequest(_) => HttpResponse::BadRequest().json(error_response),
            AppError::UserNotFound(_) => HttpResponse::NotFound().json(error_response),
            AppError::CredentialNotFound => HttpResponse::NotFound().json(error_response),
            AppError::ChallengeNotFound => HttpResponse::BadRequest().json(error_response),
            AppError::InvalidAttestation => HttpResponse::BadRequest().json(error_response),
            AppError::InvalidAssertion => HttpResponse::BadRequest().json(error_response),
            _ => HttpResponse::InternalServerError().json(error_response),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;