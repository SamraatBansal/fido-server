use crate::{
    error::{AppError, Result},
    types::*,
    simple_webauthn::SimpleWebAuthnService,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde_json::json;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub webauthn: SimpleWebAuthnService,
}

// Registration endpoints

pub async fn attestation_options(
    State(state): State<AppState>,
    Json(req): Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<Json<ServerPublicKeyCredentialCreationOptionsResponse>> {
    info!("Attestation options request for user: {}", req.username);

    // Validate input
    if req.username.is_empty() {
        return Err(AppError::InvalidInput("Username cannot be empty".to_string()));
    }

    if req.display_name.is_empty() {
        return Err(AppError::InvalidInput("Display name cannot be empty".to_string()));
    }

    let response = state
        .webauthn
        .start_registration(
            &req.username,
            &req.display_name,
            req.authenticator_selection,
            req.attestation,
        )
        .await?;

    info!(
        "Generated registration challenge for user: {}, challenge length: {}",
        req.username,
        response.challenge.len()
    );

    Ok(Json(response))
}

pub async fn attestation_result(
    State(state): State<AppState>,
    Json(req): Json<ServerPublicKeyCredential>,
) -> Result<Json<ServerResponse>> {
    info!("Attestation result for credential: {}", req.id);

    // Validate input
    if req.id.is_empty() {
        return Err(AppError::InvalidInput("Credential ID cannot be empty".to_string()));
    }

    if req.response.client_data_json.is_empty() {
        return Err(AppError::InvalidInput("Client data JSON cannot be empty".to_string()));
    }

    if req.response.attestation_object.is_empty() {
        return Err(AppError::InvalidInput("Attestation object cannot be empty".to_string()));
    }

    if req.type_ != "public-key" {
        return Err(AppError::InvalidInput("Invalid credential type".to_string()));
    }

    let response = state.webauthn.finish_registration(&req).await?;

    info!("Successfully registered credential: {}", req.id);

    Ok(Json(response))
}

// Authentication endpoints

pub async fn assertion_options(
    State(state): State<AppState>,
    Json(req): Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<Json<ServerPublicKeyCredentialGetOptionsResponse>> {
    info!("Assertion options request for user: {}", req.username);

    // Validate input
    if req.username.is_empty() {
        return Err(AppError::InvalidInput("Username cannot be empty".to_string()));
    }

    let response = state
        .webauthn
        .start_authentication(&req.username, req.user_verification)
        .await
        .map_err(|e| match e {
            AppError::UserNotFound => {
                warn!("User not found: {}", req.username);
                AppError::NotFound("User does not exist!".to_string())
            }
            AppError::CredentialNotFound => {
                warn!("No credentials found for user: {}", req.username);
                AppError::NotFound("No credentials found for user".to_string())
            }
            other => other,
        })?;

    info!(
        "Generated authentication challenge for user: {}, challenge length: {}",
        req.username,
        response.challenge.len()
    );

    Ok(Json(response))
}

pub async fn assertion_result(
    State(state): State<AppState>,
    Json(req): Json<ServerPublicKeyCredentialAssertion>,
) -> Result<Json<ServerResponse>> {
    info!("Assertion result for credential: {}", req.id);

    // Validate input
    if req.id.is_empty() {
        return Err(AppError::InvalidInput("Credential ID cannot be empty".to_string()));
    }

    if req.response.client_data_json.is_empty() {
        return Err(AppError::InvalidInput("Client data JSON cannot be empty".to_string()));
    }

    if req.response.authenticator_data.is_empty() {
        return Err(AppError::InvalidInput("Authenticator data cannot be empty".to_string()));
    }

    if req.response.signature.is_empty() {
        return Err(AppError::InvalidInput("Signature cannot be empty".to_string()));
    }

    if req.type_ != "public-key" {
        return Err(AppError::InvalidInput("Invalid credential type".to_string()));
    }

    let response = state.webauthn.finish_authentication(&req).await?;

    info!("Successfully authenticated credential: {}", req.id);

    Ok(Json(response))
}

// Health check endpoint

pub async fn health() -> Result<Json<serde_json::Value>> {
    Ok(Json(json!({
        "status": "ok",
        "service": "FIDO2 WebAuthn Server",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

// Handle 404 errors
pub async fn handler_404() -> (StatusCode, Json<ServerResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ServerResponse {
            status: "failed".to_string(),
            error_message: "Endpoint not found".to_string(),
        }),
    )
}