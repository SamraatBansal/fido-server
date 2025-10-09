use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Custom error types for the FIDO2 server
#[derive(Error, Debug)]
pub enum Fido2Error {
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid attestation")]
    InvalidAttestation,
    
    #[error("Invalid assertion")]
    InvalidAssertion,
    
    #[error("Replay attack detected")]
    ReplayAttack,
    
    #[error("User already exists")]
    UserExists,
    
    #[error("Invalid base64url encoding")]
    InvalidBase64Url,
    
    #[error("Invalid request format")]
    InvalidRequest,
    
    #[error("Internal server error")]
    InternalError,
}

impl IntoResponse for Fido2Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Fido2Error::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            Fido2Error::InvalidRequest => (StatusCode::BAD_REQUEST, "Invalid request format".to_string()),
            Fido2Error::InvalidBase64Url => (StatusCode::BAD_REQUEST, "Invalid base64url encoding".to_string()),
            Fido2Error::ChallengeNotFound | Fido2Error::InvalidChallenge => {
                (StatusCode::UNAUTHORIZED, "Challenge not found or expired".to_string())
            }
            Fido2Error::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            Fido2Error::CredentialNotFound => (StatusCode::NOT_FOUND, "Credential not found".to_string()),
            Fido2Error::InvalidAttestation | Fido2Error::InvalidAssertion => {
                (StatusCode::UNPROCESSABLE_ENTITY, "Verification failed".to_string())
            }
            Fido2Error::ReplayAttack => (StatusCode::LOCKED, "Replay attack detected".to_string()),
            Fido2Error::UserExists => (StatusCode::CONFLICT, "User already exists".to_string()),
            Fido2Error::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()),
            Fido2Error::WebAuthn(_) => (StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn error".to_string()),
            Fido2Error::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        let body = Json(json!({
            "error": status.as_str(),
            "message": error_message
        }));

        (status, body).into_response()
    }
}

/// Result type alias for convenience
pub type Fido2Result<T> = Result<T, Fido2Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn test_error_response_codes() {
        let test_cases = vec![
            (Fido2Error::Validation("test".to_string()), StatusCode::BAD_REQUEST),
            (Fido2Error::InvalidRequest, StatusCode::BAD_REQUEST),
            (Fido2Error::ChallengeNotFound, StatusCode::UNAUTHORIZED),
            (Fido2Error::UserNotFound, StatusCode::NOT_FOUND),
            (Fido2Error::InvalidAttestation, StatusCode::UNPROCESSABLE_ENTITY),
            (Fido2Error::ReplayAttack, StatusCode::LOCKED),
            (Fido2Error::UserExists, StatusCode::CONFLICT),
            (Fido2Error::InternalError, StatusCode::INTERNAL_SERVER_ERROR),
        ];

        for (error, expected_status) in test_cases {
            let response = error.into_response();
            assert_eq!(response.status(), expected_status);
        }
    }

    #[test]
    fn test_error_display() {
        let error = Fido2Error::Validation("Invalid input".to_string());
        assert_eq!(error.to_string(), "Validation error: Invalid input");
    }

    #[test]
    fn test_database_error_conversion() {
        let db_error = sqlx::Error::RowNotFound;
        let fido_error: Fido2Error = db_error.into();
        matches!(fido_error, Fido2Error::Database(_));
    }
}