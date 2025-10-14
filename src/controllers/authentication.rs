//! Authentication controller

use actix_web::{web, HttpResponse, Result};
use crate::db::models::{
    AuthenticationChallengeRequest, AuthenticationChallengeResponse,
    AuthenticationVerificationRequest
};
use crate::error::AppError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

/// Handle authentication challenge request
pub async fn authentication_challenge(
    req: web::Json<AuthenticationChallengeRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    if req.username.is_empty() {
        return Err(AppError::BadRequest("Username is required".to_string()));
    }

    // Basic email validation
    if !req.username.contains('@') {
        return Err(AppError::BadRequest("Username must be a valid email address".to_string()));
    }

    // TODO: Implement user lookup and credential retrieval
    // For now, return user not found since we haven't implemented user lookup
    Err(AppError::NotFound("User not found".to_string()))
}

/// Handle authentication verification request
pub async fn authentication_verification(
    req: web::Json<AuthenticationVerificationRequest>,
) -> Result<HttpResponse, AppError> {
    // Basic validation
    if req.credential.id.is_empty() {
        return Err(AppError::BadRequest("Credential ID is required".to_string()));
    }

    if req.credential.type_ != "public-key" {
        return Err(AppError::BadRequest("Invalid credential type".to_string()));
    }

    // TODO: Implement signature verification
    // Check if credential exists (for now, always return not found)
    Err(AppError::NotFound("Credential not found".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_authentication_challenge_missing_username() {
        let req = AuthenticationChallengeRequest {
            username: "".to_string(),
            user_verification: None,
        };

        let result = authentication_challenge(web::Json(req)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::BadRequest(msg) => assert!(msg.contains("Username is required")),
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[actix_web::test]
    async fn test_authentication_challenge_invalid_email() {
        let req = AuthenticationChallengeRequest {
            username: "invalid-email".to_string(),
            user_verification: None,
        };

        let result = authentication_challenge(web::Json(req)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::BadRequest(msg) => assert!(msg.contains("valid email")),
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[actix_web::test]
    async fn test_authentication_challenge_user_not_found() {
        let req = AuthenticationChallengeRequest {
            username: "test@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let result = authentication_challenge(web::Json(req)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert!(msg.contains("not found")),
            _ => panic!("Expected NotFound error"),
        }
    }
}