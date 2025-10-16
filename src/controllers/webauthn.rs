//! WebAuthn controllers

use actix_web::{web, HttpResponse, Result as ActixResult};
use validator::Validate;
use crate::error::AppError;
use crate::models::{
    requests::{ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredential},
    responses::ServerResponse,
};
use crate::services::WebAuthnServiceImpl;
use crate::services::WebAuthnService;

/// Handle attestation options request (credential creation)
pub async fn attestation_options(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    webauthn_service: web::Data<WebAuthnServiceImpl>,
) -> ActixResult<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_msg = format!("Validation error: {:?}", validation_errors);
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error(error_msg)));
    }

    match webauthn_service.generate_registration_challenge(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::ValidationError(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse::error(msg)))
        }
        Err(AppError::NotFound(msg)) => {
            Ok(HttpResponse::NotFound().json(ServerResponse::error(msg)))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse::error("Internal server error")))
        }
    }
}

/// Handle attestation result request (credential creation verification)
pub async fn attestation_result(
    request: web::Json<ServerPublicKeyCredential>,
    webauthn_service: web::Data<WebAuthnServiceImpl>,
) -> ActixResult<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_msg = format!("Validation error: {:?}", validation_errors);
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error(error_msg)));
    }

    match webauthn_service.verify_registration(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::ValidationError(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse::error(msg)))
        }
        Err(AppError::WebAuthnError(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse::error(format!("Can not validate response signature: {}", msg))))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse::error("Internal server error")))
        }
    }
}

/// Handle assertion options request (credential get)
pub async fn assertion_options(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    webauthn_service: web::Data<WebAuthnServiceImpl>,
) -> ActixResult<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_msg = format!("Validation error: {:?}", validation_errors);
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error(error_msg)));
    }

    match webauthn_service.generate_authentication_challenge(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::ValidationError(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse::error(msg)))
        }
        Err(AppError::NotFound(msg)) => {
            Ok(HttpResponse::NotFound().json(ServerResponse::error(msg)))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse::error("Internal server error")))
        }
    }
}

/// Handle assertion result request (credential get verification)
pub async fn assertion_result(
    request: web::Json<ServerPublicKeyCredential>,
    webauthn_service: web::Data<WebAuthnServiceImpl>,
) -> ActixResult<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_msg = format!("Validation error: {:?}", validation_errors);
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error(error_msg)));
    }

    match webauthn_service.verify_authentication(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::ValidationError(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse::error(msg)))
        }
        Err(AppError::WebAuthnError(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse::error(format!("Can not validate response signature: {}", msg))))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse::error("Internal server error")))
        }
    }
}