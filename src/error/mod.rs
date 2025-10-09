//! Error types for the FIDO2/WebAuthn server

use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    
    #[error("Invalid credential: {0}")]
    InvalidCredential(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),
    
    #[error("Invalid assertion: {0}")]
    InvalidAssertion(String),
    
    #[error("Replay attack detected")]
    ReplayAttack,
    
    #[error("Origin mismatch")]
    OriginMismatch,
    
    #[error("RP ID mismatch")]
    RpIdMismatch,
    
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl AppError {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::ValidationError(msg.into())
    }
    
    pub fn invalid_challenge(msg: impl Into<String>) -> Self {
        Self::InvalidChallenge(msg.into())
    }
    
    pub fn invalid_credential(msg: impl Into<String>) -> Self {
        Self::InvalidCredential(msg.into())
    }
    
    pub fn user_not_found(msg: impl Into<String>) -> Self {
        Self::UserNotFound(msg.into())
    }
    
    pub fn invalid_attestation(msg: impl Into<String>) -> Self {
        Self::InvalidAttestation(msg.into())
    }
    
    pub fn invalid_assertion(msg: impl Into<String>) -> Self {
        Self::InvalidAssertion(msg.into())
    }
    
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::InternalError(msg.into())
    }
}