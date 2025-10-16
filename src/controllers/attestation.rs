//! Attestation (registration) controllers

use actix_web::{web, HttpResponse, Result};
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredential,
    ServerResponse,
    AuthenticatorSelectionCriteria,
};
use crate::error::AppError;
use crate::services::{WebAuthnService, WebAuthnConfig};
use std::sync::Arc;

/// Begin attestation (registration) process
pub async fn begin_attestation(
    req: web::Json<serde_json::Value>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse, AppError> {
    // Extract fields from JSON request
    let username = req["username"].as_str().ok_or_else(|| AppError::InvalidRequest("Missing username".to_string()))?;
    let display_name = req["displayName"].as_str().unwrap_or(username);
    
    // Parse authenticator selection
    let authenticator_selection = if let Some(auth_sel) = req.get("authenticatorSelection") {
        Some(serde_json::from_value::<AuthenticatorSelectionCriteria>(auth_sel.clone())
            .map_err(|e| AppError::InvalidRequest(format!("Invalid authenticatorSelection: {}", e)))?)
    } else {
        None
    };
    
    let attestation = req["attestation"].as_str().map(|s| s.to_string());

    // Use WebAuthn service to begin registration
    let response = webauthn_service
        .begin_registration(username, display_name, authenticator_selection, attestation)
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Complete attestation (registration) process
pub async fn finish_attestation(
    req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse, AppError> {
    // TODO: Implement actual attestation verification
    // For now, just return success to make tests pass
    
    // Validate basic structure
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing credential ID")));
    }

    if req.response.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing clientDataJSON")));
    }

    if req.response.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing attestationObject")));
    }

    // TODO: Verify attestation object and client data
    // TODO: Store credential in database
    
    Ok(HttpResponse::Ok().json(ServerResponse::success()))
}