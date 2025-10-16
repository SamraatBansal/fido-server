//! Attestation (registration) controllers

use actix_web::{web, HttpResponse, Result};
use crate::models::{
    ServerPublicKeyCredential,
    ServerResponse,
    AuthenticatorSelectionCriteria,
};
use crate::error::AppError;
use crate::services::WebAuthnService;
use std::sync::Arc;
use base64::Engine;

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
    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.client_data_json) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid clientDataJSON encoding")));
    }

    // Validate attestationObject - must be valid base64url
    if req.response.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing attestationObject")));
    }

    // Try to decode attestationObject to validate it's proper base64url
    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.attestation_object) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid attestationObject encoding")));
    }

    // Parse and validate client data JSON
    let client_data_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.response.client_data_json)
        .map_err(|_| AppError::InvalidRequest("Invalid clientDataJSON encoding".to_string()))?;
    
    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| AppError::InvalidRequest("Invalid clientDataJSON format".to_string()))?;

    // Validate required fields in client data
    if !client_data.get("challenge").is_some() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing challenge field!")));
    }

    if !client_data.get("origin").is_some() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing origin field!")));
    }

    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.create") {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid client data type")));
    }

    // Use WebAuthn service to complete registration
    match webauthn_service.finish_registration(req.into_inner()).await {
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