//! Error types and handling for the WebAuthn server

use thiserror::Error;
use actix_web::{HttpResponse, ResponseError};
use validator::ValidationErrors;

/// Application error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    #[error("Invalid challenge format")]
    InvalidChallenge,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Invalid origin")]
    InvalidOrigin,
    
    #[error("Invalid RP ID")]
    InvalidRpId,
    
    #[error("Replay attack detected")]
    ReplayAttack,
    
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl From<ValidationErrors> for AppError {
    fn from(errors: ValidationErrors) -> Self {
        AppError::ValidationError(format!("Validation failed: {:?}", errors))
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            AppError::ValidationError(_) => HttpResponse::BadRequest(),
            AppError::WebAuthnError(_) => HttpResponse::BadRequest(),
            AppError::ChallengeNotFound => HttpResponse::BadRequest(),
            AppError::InvalidChallenge => HttpResponse::BadRequest(),
            AppError::CredentialNotFound => HttpResponse::NotFound(),
            AppError::UserNotFound => HttpResponse::NotFound(),
            AppError::InvalidSignature => HttpResponse::BadRequest(),
            AppError::InvalidOrigin => HttpResponse::BadRequest(),
            AppError::InvalidRpId => HttpResponse::BadRequest(),
            AppError::ReplayAttack => HttpResponse::BadRequest(),
            AppError::DatabaseError(_) => HttpResponse::InternalServerError(),
            AppError::SerializationError(_) => HttpResponse::InternalServerError(),
            AppError::Base64Error(_) => HttpResponse::BadRequest(),
            AppError::InternalError(_) => HttpResponse::InternalServerError(),
        };

        status.json(crate::schema::ServerResponse {
            status: "failed".to_string(),
            error_message: self.to_string(),
        })
    }
}

/// Result type alias for application operations
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_validation_error_response() {
        let error = AppError::ValidationError("Invalid input".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_not_found_error_response() {
        let error = AppError::UserNotFound;
        let response = error.error_response();
        
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_internal_error_response() {
        let error = AppError::InternalError("Something went wrong".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}