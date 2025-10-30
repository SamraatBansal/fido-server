use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    
    #[error("Task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

impl actix_web::error::ResponseError for AppError {
    fn error_response(&self) -> actix_web::HttpResponse {
        use actix_web::http::StatusCode;
        
        let status = match self {
            AppError::Database(_) | AppError::DatabaseConnection(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::WebAuthn(_) => StatusCode::BAD_REQUEST,
            AppError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Base64(_) => StatusCode::BAD_REQUEST,
            AppError::TaskJoin(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            AppError::UserNotFound(_) => StatusCode::NOT_FOUND,
            AppError::CredentialNotFound => StatusCode::NOT_FOUND,
            AppError::ChallengeNotFound => StatusCode::NOT_FOUND,
            AppError::InvalidChallenge => StatusCode::BAD_REQUEST,
            AppError::VerificationFailed(_) => StatusCode::UNAUTHORIZED,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let error_message = self.to_string();
        let response = crate::dtos::ServerResponse::error(error_message);

        actix_web::HttpResponse::build(status).json(response)
    }
}