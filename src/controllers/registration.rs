use crate::config::AppConfig;
use crate::db::{get_connection, DbPool};
use crate::error::{AppError, Result};
use crate::services::{FidoService, RegistrationRequest};
use actix_web::{web, HttpResponse};
use std::sync::Arc;
use webauthn_rs::prelude::*;

pub async fn attestation_options(
    pool: web::Data<DbPool>,
    config: web::Data<Arc<AppConfig>>,
    request: web::Json<RegistrationRequest>,
) -> Result<HttpResponse> {
    let mut conn = get_connection(&pool)?;
    let fido_service = FidoService::new(config.get_ref().clone())?;
    
    // Validate request
    if request.username.is_empty() {
        return Err(AppError::BadRequest("Username is required".to_string()));
    }
    
    if request.display_name.is_empty() {
        return Err(AppError::BadRequest("Display name is required".to_string()));
    }

    // Validate email format
    if !request.username.contains('@') || !request.username.contains('.') {
        return Err(AppError::Validation("Invalid email format".to_string()));
    }

    let response = fido_service.start_registration(&mut conn, request.into_inner())?;
    
    Ok(HttpResponse::Ok().json(response))
}

pub async fn attestation_result(
    pool: web::Data<DbPool>,
    config: web::Data<Arc<AppConfig>>,
    credential: web::Json<RegisterPublicKeyCredential>,
) -> Result<HttpResponse> {
    let mut conn = get_connection(&pool)?;
    let fido_service = FidoService::new(config.get_ref().clone())?;
    
    let response = fido_service.finish_registration(&mut conn, credential.into_inner())?;
    
    Ok(HttpResponse::Ok().json(response))
}