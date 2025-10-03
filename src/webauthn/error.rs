use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("WebAuthn configuration error: {0}")]
    Config(String),
    
    #[error("Registration failed: {0}")]
    Registration(String),
    
    #[error("Authentication failed: {0}")]
    Authentication(String),
    
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

impl From<webauthn_rs::error::WebauthnError> for WebAuthnError {
    fn from(err: webauthn_rs::error::WebauthnError) -> Self {
        WebAuthnError::Registration(format!("WebAuthn error: {}", err))
    }
}

impl From<serde_json::Error> for WebAuthnError {
    fn from(err: serde_json::Error) -> Self {
        WebAuthnError::Serialization(format!("JSON error: {}", err))
    }
}