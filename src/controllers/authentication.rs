use actix_web::{web, HttpResponse, Result};

use crate::{
    controllers::registration::AppState,
    error::AppError,
    schemas::{request::*, response::*},
};

pub async fn begin_authentication(
    data: web::Data<AppState>,
    req: web::Json<AuthenticationBeginRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .begin_authentication(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

pub async fn complete_authentication(
    data: web::Data<AppState>,
    req: web::Json<AuthenticationCompleteRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .complete_authentication(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}