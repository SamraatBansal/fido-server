//! WebAuthn API controllers

use actix_web::{web, HttpResponse, Result as ActixResult};
use std::sync::Arc;

use crate::schema::*;
use crate::services::WebAuthnService;

/// Handles attestation options request
pub async fn attestation_options(
    webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> ActixResult<HttpResponse> {
    match webauthn_service.generate_registration_challenge(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Attestation options error: {:?}", e);
            let error_response = ServerResponse::error(format!("Failed to generate registration options: {}", e));
            Ok(HttpResponse::BadRequest().json(error_response))
        }
    }
}

/// Handles attestation result verification
pub async fn attestation_result(
    webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
    credential: web::Json<ServerPublicKeyCredential>,
) -> ActixResult<HttpResponse> {
    match webauthn_service.verify_registration(credential.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Attestation verification error: {:?}", e);
            let error_response = ServerResponse::error(format!("Can not validate response signature!"));
            Ok(HttpResponse::BadRequest().json(error_response))
        }
    }
}

/// Handles assertion options request
pub async fn assertion_options(
    webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> ActixResult<HttpResponse> {
    match webauthn_service.generate_authentication_challenge(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Assertion options error: {:?}", e);
            let error_response = ServerResponse::error(format!("Failed to generate authentication options: {}", e));
            Ok(HttpResponse::BadRequest().json(error_response))
        }
    }
}

/// Handles assertion result verification
pub async fn assertion_result(
    webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
    credential: web::Json<ServerPublicKeyCredential>,
) -> ActixResult<HttpResponse> {
    match webauthn_service.verify_authentication(credential.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Assertion verification error: {:?}", e);
            let error_response = ServerResponse::error(format!("Can not validate response signature!"));
            Ok(HttpResponse::BadRequest().json(error_response))
        }
    }
}