//! Registration controller

use actix_web::{web, HttpResponse, Result};
use crate::db::models::{
    RegistrationChallengeRequest, RegistrationChallengeResponse, 
    RegistrationVerificationRequest,
    RelyingParty, UserEntity, PubKeyCredParam
};
use crate::error::AppError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use uuid::Uuid;

/// Handle registration challenge request
pub async fn registration_challenge(
    req: web::Json<RegistrationChallengeRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    if req.username.is_empty() {
        return Err(AppError::BadRequest("Username is required".to_string()));
    }

    if req.display_name.is_empty() {
        return Err(AppError::BadRequest("Display name is required".to_string()));
    }

    // Basic email validation
    if !req.username.contains('@') {
        return Err(AppError::BadRequest("Username must be a valid email address".to_string()));
    }

    // Generate cryptographically random challenge
    let mut challenge_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    // Generate user ID
    let user_id = Uuid::new_v4();
    let user_id_bytes = user_id.as_bytes();
    let user_id_b64 = URL_SAFE_NO_PAD.encode(user_id_bytes);

    // Create response
    let response = RegistrationChallengeResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        rp: RelyingParty {
            name: "FIDO Server".to_string(),
            id: Some("localhost".to_string()),
        },
        user: UserEntity {
            id: user_id_b64,
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        challenge,
        pub_key_cred_params: vec![
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -7, // ES256
            },
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: 60000,
        exclude_credentials: vec![], // TODO: Implement credential lookup
        authenticator_selection: req.authenticator_selection.clone(),
        attestation: req.attestation.clone().unwrap_or_else(|| "none".to_string()),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Handle registration verification request
pub async fn registration_verification(
    req: web::Json<RegistrationVerificationRequest>,
) -> Result<HttpResponse, AppError> {
    // Basic validation
    if req.credential.id.is_empty() {
        return Err(AppError::BadRequest("Credential ID is required".to_string()));
    }

    if req.credential.type_ != "public-key" {
        return Err(AppError::BadRequest("Invalid credential type".to_string()));
    }

    // For now, return a basic error since we haven't implemented full verification
    // This will be implemented in the next iteration
    Err(AppError::WebAuthnError("Attestation verification not yet implemented".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn test_registration_challenge_valid_request() {
        let req = RegistrationChallengeRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = registration_challenge(web::Json(req)).await;
        assert!(result.is_ok());
    }

    #[actix_web::test]
    async fn test_registration_challenge_empty_username() {
        let req = RegistrationChallengeRequest {
            username: "".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = registration_challenge(web::Json(req)).await;
        assert!(result.is_err());
    }

    #[actix_web::test]
    async fn test_registration_challenge_invalid_email() {
        let req = RegistrationChallengeRequest {
            username: "invalid-email".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = registration_challenge(web::Json(req)).await;
        assert!(result.is_err());
    }
}