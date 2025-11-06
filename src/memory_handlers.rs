use crate::api::*;
use crate::error::Result;
use crate::memory_service::MemoryWebAuthnService;
use crate::validation::*;
use actix_web::{web, HttpResponse};

pub async fn start_registration(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    validate_registration_request(&request)?;
    
    let response = service.start_registration(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_registration(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    validate_registration_credential(&credential)?;
    
    let response = service.finish_registration(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn start_authentication(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    validate_authentication_request(&request)?;
    
    let response = service.start_authentication(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_authentication(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    validate_authentication_credential(&credential)?;
    
    let response = service.finish_authentication(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(ServerResponse::success())
}