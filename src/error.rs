use thiserror::Error;
use actix_web::{HttpResponse, ResponseError};
use serde_json::json;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
    
    #[error("Invalid display name: {0}")]
    InvalidDisplayName(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("User already exists: {0}")]
    UserAlreadyExists(String),
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Challenge not found")]
    ChallengeNotFound,
    
    #[error("Invalid attestation")]
    InvalidAttestation,
    
    #[error("Invalid assertion")]
    InvalidAssertion,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid credential")]
    InvalidCredential,
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Origin validation failed")]
    OriginValidationFailed,
    
    #[error("RP ID validation failed")]
    RpIdValidationFailed,
    
    #[error("User verification failed")]
    UserVerificationFailed,
    
    #[error("Counter replay detected")]
    CounterReplayDetected,
    
    #[error("Invalid base64url encoding: {0}")]
    InvalidBase64Url(String),
    
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("WebAuthn library error: {0}")]
    WebAuthnLibError(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Request timeout")]
    RequestTimeout,
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Field validation failed: {field} - {reason}")]
    FieldValidationFailed { field: String, reason: String },
}

impl ResponseError for WebAuthnError {
    fn error_response(&self) -> HttpResponse {
        let (status_code, error_message) = match self {
            WebAuthnError::InvalidUsername(_) |
            WebAuthnError::InvalidDisplayName(_) |
            WebAuthnError::InvalidChallenge |
            WebAuthnError::InvalidAttestation |
            WebAuthnError::InvalidAssertion |
            WebAuthnError::InvalidCredential |
            WebAuthnError::InvalidBase64Url(_) |
            WebAuthnError::InvalidJson(_) |
            WebAuthnError::InvalidRequest(_) |
            WebAuthnError::MissingField(_) |
            WebAuthnError::FieldValidationFailed { .. } => {
                (actix_web::http::StatusCode::BAD_REQUEST, self.to_string())
            },
            
            WebAuthnError::UserNotFound(_) |
            WebAuthnError::ChallengeNotFound |
            WebAuthnError::CredentialNotFound => {
                (actix_web::http::StatusCode::NOT_FOUND, self.to_string())
            },
            
            WebAuthnError::UserAlreadyExists(_) => {
                (actix_web::http::StatusCode::CONFLICT, self.to_string())
            },
            
            WebAuthnError::ChallengeExpired |
            WebAuthnError::SignatureVerificationFailed |
            WebAuthnError::OriginValidationFailed |
            WebAuthnError::RpIdValidationFailed |
            WebAuthnError::UserVerificationFailed |
            WebAuthnError::CounterReplayDetected => {
                (actix_web::http::StatusCode::UNAUTHORIZED, self.to_string())
            },
            
            WebAuthnError::RateLimitExceeded => {
                (actix_web::http::StatusCode::TOO_MANY_REQUESTS, self.to_string())
            },
            
            WebAuthnError::RequestTimeout => {
                (actix_web::http::StatusCode::REQUEST_TIMEOUT, self.to_string())
            },
            
            WebAuthnError::DatabaseError(_) |
            WebAuthnError::WebAuthnLibError(_) |
            WebAuthnError::InternalError(_) => {
                (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
        };

        HttpResponse::build(status_code).json(json!({
            "status": "failed",
            "errorMessage": error_message
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_invalid_username_error() {
        let error = WebAuthnError::InvalidUsername("test@example.com".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_user_not_found_error() {
        let error = WebAuthnError::UserNotFound("test@example.com".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_user_already_exists_error() {
        let error = WebAuthnError::UserAlreadyExists("test@example.com".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_signature_verification_failed_error() {
        let error = WebAuthnError::SignatureVerificationFailed;
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_rate_limit_exceeded_error() {
        let error = WebAuthnError::RateLimitExceeded;
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_internal_error() {
        let error = WebAuthnError::InternalError("Database connection failed".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_field_validation_error() {
        let error = WebAuthnError::FieldValidationFailed {
            field: "username".to_string(),
            reason: "must be a valid email".to_string(),
        };
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_missing_field_error() {
        let error = WebAuthnError::MissingField("username".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}