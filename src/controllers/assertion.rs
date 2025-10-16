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

    // Use WebAuthn service to complete authentication
    webauthn_service
        .finish_authentication(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(ServerResponse::success()))
}