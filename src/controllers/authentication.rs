//! Authentication controller

use actix_web::{web, HttpResponse, Result as ActixResult};

use crate::{
    schema::{
        ServerPublicKeyCredentialGetOptionsRequest,
        ServerPublicKeyCredentialGetOptionsResponse,
        ServerPublicKeyCredentialAssertion,
        ServerResponse,
    },
    services::FidoService,
    AppError,
};

pub async fn assertion_options(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    fido_service: web::Data<FidoService>,
) -> ActixResult<HttpResponse> {
    match fido_service.start_authentication(&req).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Authentication start error: {}", e);
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: e.sanitized_message(),
            }))
        }
    }
}

pub async fn assertion_result(
    req: web::Json<ServerPublicKeyCredentialAssertion>,
    fido_service: web::Data<FidoService>,
) -> ActixResult<HttpResponse> {
    match fido_service.finish_authentication(&req).await {
        Ok(()) => Ok(HttpResponse::Ok().json(ServerResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
        })),
        Err(e) => {
            log::error!("Authentication finish error: {}", e);
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: e.sanitized_message(),
            }))
        }
    }
}