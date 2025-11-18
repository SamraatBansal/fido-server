//! Custom error types for the FIDO server

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use std::fmt;
use webauthn_rs::prelude::WebauthnError;

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    /// WebAuthn error
    #[error("WebAuthn error: {0}")]
    WebAuthnError(#[from] WebauthnError),
    
    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Internal server error
    #[error("Internal error: {0}")]
    InternalError(String),
    
    /// Bad request error
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    /// Security error
    #[error("Security error: {0}")]
    SecurityError(String),
    
    /// Challenge error
    #[error("Challenge error: {0}")]
    ChallengeError(String),
    
    /// Credential error
    #[error("Credential error: {0}")]
    CredentialError(String),
}

impl AppError {
    pub fn is_security_sensitive(&self) -> bool {
        matches!(
            self,
            Self::SecurityError(_) | 
            Self::ChallengeError(_) |
            Self::WebAuthnError(_)
        )
    }
    
    pub fn sanitized_message(&self) -> String {
        if self.is_security_sensitive() {
            "Authentication failed".to_string()
        } else {
            self.to_string()
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = self.sanitized_message();

        HttpResponse::build(status_code).json(serde_json::json!({
            "status": "failed",
            "errorMessage": error_message
        }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseError(_) | Self::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::WebAuthnError(_) | Self::SecurityError(_) | Self::ChallengeError(_) | Self::CredentialError(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::ValidationError(_) | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

impl std::error::Error for AppError {}
