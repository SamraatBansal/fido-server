use crate::config::AppConfig;
use crate::db::{get_connection, DbPool};
use crate::error::{AppError, Result};
use crate::services::{AuthenticationRequest, FidoService};
use actix_web::{web, HttpResponse};
use std::sync::Arc;
use webauthn_rs::prelude::*;

pub async fn assertion_options(
    pool: web::Data<DbPool>,
    config: web::Data<Arc<AppConfig>>,
    request: web::Json<AuthenticationRequest>,
) -> Result<HttpResponse> {
    let mut conn = get_connection(&pool)?;
    let fido_service = FidoService::new(config.get_ref().clone())?;
    
    // Validate request
    if request.username.is_empty() {
        return Err(AppError::BadRequest("Username is required".to_string()));
    }

    // Validate user verification requirement
    if let Some(ref uv) = request.user_verification {
        match uv {
            UserVerificationPolicy::Required 
            | UserVerificationPolicy::Preferred 
            | UserVerificationPolicy::Discouraged => {},
            _ => return Err(AppError::Validation("Invalid user verification requirement".to_string())),
        }
    }

    let response = fido_service.start_authentication(&mut conn, request.into_inner())?;
    
    Ok(HttpResponse::Ok().json(response))
}

pub async fn assertion_result(
    pool: web::Data<DbPool>,
    config: web::Data<Arc<AppConfig>>,
    credential: web::Json<PublicKeyCredential>,
) -> Result<HttpResponse> {
    let mut conn = get_connection(&pool)?;
    let fido_service = FidoService::new(config.get_ref().clone())?;
    
    let response = fido_service.finish_authentication(&mut conn, credential.into_inner())?;
    
    Ok(HttpResponse::Ok().json(response))
}