//! Attestation (registration) controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use crate::services::{WebAuthnService, UserService};
use crate::schema::user::CreateUserRequest;
use crate::schema::webauthn::{AttestationResponse};

/// Handle attestation options request
pub async fn attestation_options(
    webauthn_service: web::Data<WebAuthnService>,
    _user_service: web::Data<UserService>,
    request: web::Json<CreateUserRequest>,
) -> Result<HttpResponse> {
    match webauthn_service.generate_registration_challenge(&request.username, &request.display_name).await {
        Ok(options) => Ok(HttpResponse::Ok().json(options)),
        Err(e) => {
            tracing::error!("Failed to generate attestation options: {}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": e.to_string()
            })))
        }
    }
}

/// Handle attestation result request
pub async fn attestation_result(
    webauthn_service: web::Data<WebAuthnService>,
    request: web::Json<AttestationResponse>,
) -> Result<HttpResponse> {
    // TODO: Get challenge ID from request or session
    let challenge_id = "mock_challenge_id";
    
    match webauthn_service.verify_registration(&request, challenge_id).await {
        Ok(result) => Ok(HttpResponse::Ok().json(result)),
        Err(e) => {
            tracing::error!("Failed to verify attestation: {}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": e.to_string()
            })))
        }
    }
}