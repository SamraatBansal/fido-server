//! Error module

use thiserror::Error;

/// Main error type for the FIDO2 server
#[derive(Debug, Error)]
pub enum FidoError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Challenge already used")]
    ChallengeAlreadyUsed,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Counter replay detected")]
    CounterReplay,
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

/// Result type alias
pub type FidoResult<T> = Result<T, FidoError>;