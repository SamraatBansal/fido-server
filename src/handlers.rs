use actix_web::{web, HttpResponse, ResponseError, Result as ActixResult};

use crate::api_types::*;
use crate::webauthn_service::WebAuthnService;

pub async fn start_registration(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    webauthn_service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    log::debug!("Start registration request: {:?}", request);

    match webauthn_service.start_registration(request.into_inner()).await {
        Ok(response) => {
            log::debug!("Registration started successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Registration start failed: {}", e);
            Ok(e.error_response())
        }
    }
}

pub async fn finish_registration(
    credential: web::Json<ServerPublicKeyCredential>,
    webauthn_service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    log::debug!("Finish registration request: {:?}", credential);

    match webauthn_service.finish_registration(credential.into_inner()).await {
        Ok(response) => {
            log::debug!("Registration finished successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Registration finish failed: {}", e);
            Ok(e.error_response())
        }
    }
}

pub async fn start_authentication(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    webauthn_service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    log::debug!("Start authentication request: {:?}", request);

    match webauthn_service.start_authentication(request.into_inner()).await {
        Ok(response) => {
            log::debug!("Authentication started successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Authentication start failed: {}", e);
            Ok(e.error_response())
        }
    }
}

pub async fn finish_authentication(
    credential: web::Json<ServerPublicKeyCredential>,
    webauthn_service: web::Data<WebAuthnService>,
) -> ActixResult<HttpResponse> {
    log::debug!("Finish authentication request: {:?}", credential);

    match webauthn_service.finish_authentication(credential.into_inner()).await {
        Ok(response) => {
            log::debug!("Authentication finished successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Authentication finish failed: {}", e);
            Ok(e.error_response())
        }
    }
}

pub async fn health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}