use crate::api::*;
use crate::error::Result;
use crate::conformance_service::ConformanceWebAuthnService;
use actix_web::{web, HttpResponse};

pub async fn start_registration(
    request: JsonExtractor<ServerPublicKeyCredentialCreationOptionsRequest>,
    service: web::Data<ConformanceWebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.start_registration(&*request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_registration(
    credential: JsonExtractor<ServerPublicKeyCredential>,
    service: web::Data<ConformanceWebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.finish_registration(&*credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn start_authentication(
    request: JsonExtractor<ServerPublicKeyCredentialGetOptionsRequest>,
    service: web::Data<ConformanceWebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.start_authentication(&*request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_authentication(
    credential: JsonExtractor<ServerPublicKeyCredential>,
    service: web::Data<ConformanceWebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.finish_authentication(&*credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(ServerResponse::success())
}