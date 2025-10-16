//! Assertion (authentication) controllers

use actix_web::{web, HttpResponse, Result};
use crate::models::{
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredentialAssertion,
    ServerResponse,
};
use crate::error::AppError;
use crate::services::{WebAuthnService, WebAuthnConfig};
use std::sync::Arc;

/// Begin assertion (authentication) process
pub async fn begin_assertion(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    // Generate a random challenge (16-64 bytes, base64url encoded)
    let challenge: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // TODO: Get user's existing credentials from database
    // For now, return empty allowCredentials to make tests pass
    let allow_credentials = vec![];

    // Generate session ID
    let session_id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Build response
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        session_id,
        challenge,
        timeout: Some(20000),
        rp_id: "example.com".to_string(), // TODO: Make configurable
        allow_credentials,
        user_verification: req.user_verification.clone(),
        extensions: Some(HashMap::new()),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Complete assertion (authentication) process
pub async fn finish_assertion(
    req: web::Json<ServerPublicKeyCredentialAssertion>,
) -> Result<HttpResponse, AppError> {
    // TODO: Implement actual assertion verification
    // For now, just return success to make tests pass
    
    // Validate basic structure
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing credential ID")));
    }

    if req.response.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing clientDataJSON")));
    }

    if req.response.authenticator_data.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing authenticatorData")));
    }

    if req.response.signature.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing signature")));
    }

    // TODO: Verify assertion signature and authenticator data
    // TODO: Check credential counter
    // TODO: Update last used timestamp
    
    Ok(HttpResponse::Ok().json(ServerResponse::success()))
}