//! Assertion (Authentication) controller for FIDO2/WebAuthn

use actix_web::{web, HttpResponse, Result, ResponseError};
use std::sync::Arc;
use crate::dto::{
    ServerPublicKeyCredentialGetOptionsRequest,
    AssertionResultRequest,
};
use crate::services::fido::FidoService;

/// Handle /assertion/options endpoint
/// Generates credential request options for authentication
pub async fn assertion_options(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    fido_service: web::Data<Arc<FidoService>>,
) -> Result<HttpResponse> {
    match fido_service.start_authentication(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Authentication start error: {:?}", e);
            Ok(e.error_response())
        }
    }
}

/// Handle /assertion/result endpoint
/// Verifies assertion response and completes authentication
pub async fn assertion_result(
    request: web::Json<AssertionResultRequest>,
    fido_service: web::Data<Arc<FidoService>>,
) -> Result<HttpResponse> {
    match fido_service.complete_authentication(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Authentication completion error: {:?}", e);
            Ok(e.error_response())
        }
    }
}