use crate::config::AppConfig;
use crate::models::*;
use crate::services::WebAuthnService;
use actix_web::{web, HttpResponse, Result};
use std::sync::Arc;

// Global service instance for simplicity
lazy_static::lazy_static! {
    static ref WEBAUTHN_SERVICE: Arc<WebAuthnService> = {
        let config = AppConfig::from_env();
        Arc::new(WebAuthnService::new(&config).expect("Failed to create WebAuthn service"))
    };
}

// Registration endpoints
#[actix_web::post("/attestation/options")]
pub async fn attestation_options(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse> {
    match WEBAUTHN_SERVICE.begin_registration(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(err) => Ok(err.error_response()),
    }
}

#[actix_web::post("/attestation/result")]
pub async fn attestation_result(
    credential: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    match WEBAUTHN_SERVICE.finish_registration(credential.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(err) => Ok(err.error_response()),
    }
}

// Authentication endpoints
#[actix_web::post("/assertion/options")]
pub async fn assertion_options(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    match WEBAUTHN_SERVICE.begin_authentication(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(err) => Ok(err.error_response()),
    }
}

#[actix_web::post("/assertion/result")]
pub async fn assertion_result(
    credential: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    match WEBAUTHN_SERVICE.finish_authentication(credential.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(err) => Ok(err.error_response()),
    }
}

// Legacy endpoints (without /api/v1 prefix) for conformance testing
#[actix_web::post("/attestation/options")]
pub async fn attestation_options_legacy(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse> {
    attestation_options(request).await
}

#[actix_web::post("/attestation/result")]
pub async fn attestation_result_legacy(
    credential: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    attestation_result(credential).await
}

#[actix_web::post("/assertion/options")]
pub async fn assertion_options_legacy(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    assertion_options(request).await
}

#[actix_web::post("/assertion/result")]
pub async fn assertion_result_legacy(
    credential: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    assertion_result(credential).await
}