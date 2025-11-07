use actix_web::{web, HttpResponse, Result};
use std::sync::Arc;

use crate::{
    db::DbPool,
    error::AppError,
    schemas::{request::*, response::*},
    services::WebAuthnService,
};

pub async fn begin_registration(
    data: web::Data<AppState>,
    req: web::Json<RegistrationBeginRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .begin_registration(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

pub async fn complete_registration(
    data: web::Data<AppState>,
    req: web::Json<RegistrationCompleteRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .complete_registration(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

pub struct AppState {
    pub webauthn_service: WebAuthnService,
    pub db_pool: Arc<DbPool>,
}