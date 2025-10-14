//! Attestation (Registration) controller for FIDO2/WebAuthn

use actix_web::{web, HttpResponse, Result, ResponseError};
use std::sync::Arc;
use crate::dto::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    AttestationResultRequest,
};
use crate::services::fido::FidoService;

/// Handle /attestation/options endpoint
/// Generates credential creation options for registration
pub async fn attestation_options(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    fido_service: web::Data<Arc<FidoService>>,
) -> Result<HttpResponse> {
    match fido_service.start_registration(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Registration start error: {:?}", e);
            Ok(e.error_response())
        }
    }
}

/// Handle /attestation/result endpoint  
/// Verifies attestation response and completes registration
pub async fn attestation_result(
    request: web::Json<AttestationResultRequest>,
    fido_service: web::Data<Arc<FidoService>>,
) -> Result<HttpResponse> {
    match fido_service.complete_registration(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Registration completion error: {:?}", e);
            Ok(e.error_response())
        }
    }
}