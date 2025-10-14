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

    // For now, return user not found since we haven't implemented user lookup
    // This will be implemented when we add database integration
    return Err(AppError::NotFound("User not found".to_string()));

    // TODO: Implement user lookup and credential retrieval
    // Generate cryptographically random challenge
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    // Create response (this code will be reached after user lookup is implemented)
    let response = AuthenticationChallengeResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        challenge,
        allow_credentials: vec![], // TODO: Load user's credentials
        user_verification: req.user_verification.clone().unwrap_or_else(|| "preferred".to_string()),
        timeout: 60000,
        rp_id: "localhost".to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
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

    // Check if credential exists (for now, always return not found)
    return Err(AppError::NotFound("Credential not found".to_string()));

    // TODO: Implement signature verification
    // For now, return error for invalid signature
    Err(AppError::WebAuthnError("Can not validate response signature!".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

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