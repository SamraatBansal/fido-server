//! Authentication controller

use actix_web::{web, HttpResponse, Result as ActixResult};

use crate::dto::*;
use crate::error::{AppError, Result};
use crate::services::FidoService;

/// Start authentication endpoint
/// POST /assertion/options
pub async fn start_authentication(
    fido_service: web::Data<FidoService>,
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> ActixResult<HttpResponse> {
    log::info!("Starting authentication for user: {}", request.username);

    match fido_service.start_authentication(&request).await {
        Ok(response) => {
            log::info!("Authentication started successfully for user: {}", request.username);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to start authentication for user {}: {}", request.username, e);
            Ok(e.error_response())
        }
    }
}

/// Finish authentication endpoint
/// POST /assertion/result
pub async fn finish_authentication(
    fido_service: web::Data<FidoService>,
    request: web::Json<AuthenticationResultRequest>,
) -> ActixResult<HttpResponse> {
    log::info!("Finishing authentication for credential: {}", request.credential.id);

    match fido_service.finish_authentication(&request).await {
        Ok(response) => {
            log::info!("Authentication completed successfully for credential: {}", request.credential.id);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to complete authentication for credential {}: {}", request.credential.id, e);
            Ok(e.error_response())
        }
    }
}