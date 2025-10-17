//! WebAuthn controllers

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::services::WebAuthnService;
use crate::types::*;

/// Handle credential creation options request
pub async fn attestation_options(
    webauthn_service: web::Data<WebAuthnService>,
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    let response = webauthn_service
        .credential_creation_options(request.into_inner())
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Handle attestation result verification
pub async fn attestation_result(
    webauthn_service: web::Data<WebAuthnService>,
    request: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse, AppError> {
    let response = webauthn_service
        .verify_attestation(request.into_inner())
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Handle credential get options request
pub async fn assertion_options(
    webauthn_service: web::Data<WebAuthnService>,
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    let response = webauthn_service
        .credential_get_options(request.into_inner())
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Handle assertion result verification
pub async fn assertion_result(
    webauthn_service: web::Data<WebAuthnService>,
    request: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse, AppError> {
    let response = webauthn_service
        .verify_assertion(request.into_inner())
        .await?;

    Ok(HttpResponse::Ok().json(response))
}