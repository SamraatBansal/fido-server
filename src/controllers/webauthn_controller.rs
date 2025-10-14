//! WebAuthn controller for handling HTTP requests

use actix_web::{web, HttpRequest, HttpResponse};
use crate::error::{AppError, Result};
use crate::models::*;
use crate::services::{WebAuthnService, UserService, CredentialService};
use crate::services::webauthn_service::WebAuthnConfig;
use std::sync::Arc;

/// WebAuthn controller state
pub struct WebAuthnControllerState {
    pub webauthn_service: Arc<WebAuthnService>,
    pub user_service: Arc<UserService>,
    pub credential_service: Arc<CredentialService>,
}

impl WebAuthnControllerState {
    pub fn new() -> Result<Self> {
        let webauthn_service = Arc::new(WebAuthnService::new(WebAuthnConfig::default())?);
        let user_service = Arc::new(UserService::new());
        let credential_service = Arc::new(CredentialService::new());

        Ok(Self {
            webauthn_service,
            user_service,
            credential_service,
        })
    }
}

/// Generate registration challenge
pub async fn attestation_options(
    state: web::Data<WebAuthnControllerState>,
    _req: HttpRequest,
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if request.username.is_empty() {
        return Err(AppError::bad_request("Username is required"));
    }
    
    if request.displayName.is_empty() {
        return Err(AppError::bad_request("Display name is required"));
    }

    // Create user if doesn't exist
    if !state.user_service.user_exists(&request.username) {
        state.user_service.create_user(&request.username, &request.displayName)?;
    }

    // Generate challenge
    let response = state.webauthn_service.generate_registration_challenge(&request)?;

    Ok(HttpResponse::Ok().json(response))
}

/// Verify registration response
pub async fn attestation_result(
    state: web::Data<WebAuthnControllerState>,
    _req: HttpRequest,
    request: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    // Validate request
    if request.id.is_empty() {
        return Err(AppError::bad_request("Credential ID is required"));
    }

    // Extract username from request (for now, we'll need to pass it separately)
    // In a real implementation, this would come from the challenge state
    let username = "johndoe@example.com"; // Placeholder

    // Verify registration
    let response = state.webauthn_service.verify_registration(&request, username)?;

    Ok(HttpResponse::Ok().json(response))
}

/// Generate authentication challenge
pub async fn assertion_options(
    state: web::Data<WebAuthnControllerState>,
    _req: HttpRequest,
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if request.username.is_empty() {
        return Err(AppError::bad_request("Username is required"));
    }

    // Check if user exists
    if !state.user_service.user_exists(&request.username) {
        return Err(AppError::not_found("User does not exist"));
    }

    // Generate challenge
    let response = state.webauthn_service.generate_authentication_challenge(&request)?;

    Ok(HttpResponse::Ok().json(response))
}

/// Verify authentication response
pub async fn assertion_result(
    state: web::Data<WebAuthnControllerState>,
    _req: HttpRequest,
    request: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    // Validate request
    if request.id.is_empty() {
        return Err(AppError::bad_request("Credential ID is required"));
    }

    // Extract username from request (for now, we'll need to pass it separately)
    // In a real implementation, this would come from the challenge state
    let username = "johndoe@example.com"; // Placeholder

    // Verify authentication
    let response = state.webauthn_service.verify_authentication(&request, username)?;

    Ok(HttpResponse::Ok().json(response))
}