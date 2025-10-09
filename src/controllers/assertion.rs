//! Assertion (authentication) controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use crate::services::{WebAuthnService, UserService};
use crate::schema::webauthn::{AssertionResponse};

/// Handle assertion options request
pub async fn assertion_options(
    webauthn_service: web::Data<WebAuthnService>,
    user_service: web::Data<UserService>,
    request: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let username = request.get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing username"))?;

    match webauthn_service.generate_authentication_challenge(username).await {
        Ok(options) => Ok(HttpResponse::Ok().json(options)),
        Err(e) => {
            tracing::error!("Failed to generate assertion options: {}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": e.to_string()
            })))
        }
    }
}

/// Handle assertion result request
pub async fn assertion_result(
    webauthn_service: web::Data<WebAuthnService>,
    request: web::Json<AssertionResponse>,
) -> Result<HttpResponse> {
    // TODO: Get challenge ID from request or session
    let challenge_id = "mock_challenge_id";
    
    match webauthn_service.verify_authentication(&request, challenge_id).await {
        Ok(result) => Ok(HttpResponse::Ok().json(result)),
        Err(e) => {
            tracing::error!("Failed to verify assertion: {}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": e.to_string()
            })))
        }
    }
}