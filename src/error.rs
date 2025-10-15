use actix_web::{HttpResponse, ResponseError};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    #[error("Challenge error: {0}")]
    ChallengeError(String),
    
    #[error("Credential error: {0}")]
    CredentialError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid origin")]
    InvalidOrigin,
    
    #[error("Challenge expired or invalid")]
    InvalidChallenge,
    
    #[error("Replay attack detected")]
    ReplayAttack,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        use crate::models::ServerResponse;
        
        let (status_code, error_message) = match self {
            AppError::ValidationError(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg.clone()),
            AppError::AuthenticationError(msg) => (actix_web::http::StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::UserNotFound => (actix_web::http::StatusCode::NOT_FOUND, "User does not exist!".to_string()),
            AppError::CredentialNotFound => (actix_web::http::StatusCode::NOT_FOUND, "Credential not found".to_string()),
            AppError::InvalidOrigin => (actix_web::http::StatusCode::BAD_REQUEST, "Invalid origin".to_string()),
            AppError::InvalidChallenge => (actix_web::http::StatusCode::BAD_REQUEST, "Invalid or expired challenge".to_string()),
            AppError::ReplayAttack => (actix_web::http::StatusCode::BAD_REQUEST, "Replay attack detected".to_string()),
            AppError::ChallengeError(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg.clone()),
            AppError::CredentialError(msg) => (actix_web::http::StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        HttpResponse::build(status_code).json(ServerResponse::failed(&error_message))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;