//! Assertion (authentication) controllers

use actix_web::{web, HttpResponse, Result};
use crate::models::{
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialAssertion,
    ServerResponse,
};
use crate::error::AppError;
use crate::services::WebAuthnService;
use std::sync::Arc;
use base64::Engine;

/// Begin assertion (authentication) process
pub async fn begin_assertion(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse, AppError> {
    // Use WebAuthn service to begin authentication
    let response = webauthn_service
        .begin_authentication(&req.username, req.user_verification.clone())
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Complete assertion (authentication) process
pub async fn finish_assertion(
    req: web::Json<ServerPublicKeyCredentialAssertion>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse, AppError> {
    // Validate credential type
    if req.cred_type != "public-key" {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid credential type")));
    }

    // Validate basic structure
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing credential ID")));
    }

    // Validate clientDataJSON - must be valid base64url
    if req.response.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing clientDataJSON")));
    }

    // Try to decode clientDataJSON to validate it's proper base64url
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.client_data_json).is_err() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid clientDataJSON encoding")));
    }

    // Validate authenticatorData - must be valid base64url
    if req.response.authenticator_data.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing authenticatorData")));
    }

    // Try to decode authenticatorData to validate it's proper base64url
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.authenticator_data).is_err() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid authenticatorData encoding")));
    }

    // Validate signature - must be valid base64url
    if req.response.signature.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing signature")));
    }

    // Try to decode signature to validate it's proper base64url
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.signature).is_err() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid signature encoding")));
    }

    // Parse and validate client data JSON
    let client_data_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.client_data_json) {
        Ok(data) => data,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid clientDataJSON encoding")));
        }
    };
    
    let client_data: serde_json::Value = match serde_json::from_slice(&client_data_bytes) {
        Ok(data) => data,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid clientDataJSON format")));
        }
    };

    // Validate required fields in client data
    if !client_data.get("challenge").is_some() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing challenge field!")));
    }

    if !client_data.get("origin").is_some() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing origin field!")));
    }

    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid client data type")));
    }

    // Use WebAuthn service to complete authentication
    match webauthn_service.finish_authentication(req.into_inner()).await {
        Ok(()) => Ok(HttpResponse::Ok().json(ServerResponse::success())),
        Err(e) => {
            match e {
                AppError::InvalidRequest(msg) => {
                    Ok(HttpResponse::BadRequest().json(ServerResponse::error(format!("Can not validate response signature: {}", msg))))
                }
                _ => Ok(HttpResponse::BadRequest().json(ServerResponse::error("Can not validate response signature!")))
            }
        }
    }
}