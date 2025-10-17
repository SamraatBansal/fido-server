//! WebAuthn API controllers

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::models::webauthn::*;
use crate::services::webauthn_service::WebAuthnService;
use std::sync::Arc;

/// WebAuthn controller state
pub struct WebAuthnController {
    service: Arc<WebAuthnService>,
}

impl WebAuthnController {
    /// Create a new WebAuthn controller
    pub fn new(service: Arc<WebAuthnService>) -> Self {
        Self { service }
    }
}

/// Generate registration challenge options
#[actix_web::post("/attestation/options")]
pub async fn registration_challenge(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, AppError> {
    let response = controller
        .service
        .generate_registration_challenge(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

/// Verify registration attestation
#[actix_web::post("/attestation/result")]
pub async fn registration_result(
    req: web::Json<ServerPublicKeyCredential>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, AppError> {
    let response = controller
        .service
        .verify_registration_attestation(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

/// Generate authentication challenge options
#[actix_web::post("/assertion/options")]
pub async fn authentication_challenge(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, AppError> {
    let response = controller
        .service
        .generate_authentication_challenge(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

/// Verify authentication assertion
#[actix_web::post("/assertion/result")]
pub async fn authentication_result(
    req: web::Json<ServerPublicKeyCredential>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, AppError> {
    let response = controller
        .service
        .verify_authentication_assertion(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}