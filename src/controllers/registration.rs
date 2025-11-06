//! Registration controller

use actix_web::{web, HttpResponse, Result as ActixResult};

use crate::dto::*;
use crate::error::{AppError, Result};
use crate::services::FidoService;

/// Start registration endpoint
/// POST /attestation/options
pub async fn start_registration(
    fido_service: web::Data<FidoService>,
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> ActixResult<HttpResponse> {
    log::info!("Starting registration for user: {}", request.username);

    match fido_service.start_registration(&request).await {
        Ok(response) => {
            log::info!("Registration started successfully for user: {}", request.username);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to start registration for user {}: {}", request.username, e);
            Ok(e.error_response())
        }
    }
}

/// Finish registration endpoint
/// POST /attestation/result
pub async fn finish_registration(
    fido_service: web::Data<FidoService>,
    request: web::Json<RegistrationResultRequest>,
) -> ActixResult<HttpResponse> {
    log::info!("Finishing registration for credential: {}", request.credential.id);

    match fido_service.finish_registration(&request).await {
        Ok(response) => {
            log::info!("Registration completed successfully for credential: {}", request.credential.id);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to complete registration for credential {}: {}", request.credential.id, e);
            Ok(e.error_response())
        }
    }
}