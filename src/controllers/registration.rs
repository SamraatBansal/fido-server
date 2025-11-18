//! Registration controller

use actix_web::{web, HttpResponse, Result as ActixResult};

use crate::{
    schema::{
        ServerPublicKeyCredentialCreationOptionsRequest,
        ServerPublicKeyCredentialCreationOptionsResponse,
        ServerPublicKeyCredential,
        ServerResponse,
    },
    services::FidoService,
    AppError,
};

pub async fn attestation_options(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    fido_service: web::Data<FidoService>,
) -> ActixResult<HttpResponse> {
    match fido_service.start_registration(&req).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Registration start error: {}", e);
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: e.sanitized_message(),
            }))
        }
    }
}

pub async fn attestation_result(
    req: web::Json<ServerPublicKeyCredential>,
    fido_service: web::Data<FidoService>,
) -> ActixResult<HttpResponse> {
    match fido_service.finish_registration(&req).await {
        Ok(()) => Ok(HttpResponse::Ok().json(ServerResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
        })),
        Err(e) => {
            log::error!("Registration finish error: {}", e);
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: e.sanitized_message(),
            }))
        }
    }
}