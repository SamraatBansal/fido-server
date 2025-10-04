//! Authentication controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use webauthn_rs::prelude::*;

use crate::{
    error::AppError,
    schema::requests::{AuthenticationFinishRequest, AuthenticationStartRequest},
    schema::responses::{AuthenticationStartResponse, AuthenticationFinishResponse},
    services::{FidoService, UserService},
};

/// Start authentication process
pub async fn start_authentication(
    req: web::Json<AuthenticationStartRequest>,
    fido_service: web::Data<FidoService>,
    user_service: web::Data<UserService>,
) -> Result<HttpResponse> {
    let user = user_service
        .get_user_by_username(&req.username)
        .await?
        .ok_or(AppError::AuthenticationFailed("User not found".to_string()))?;

    let response = fido_service
        .start_authentication(&user, req.user_verification)
        .await?;

    let start_response = AuthenticationStartResponse {
        challenge: response.challenge.as_str().to_string(),
        allow_credentials: response.allow_credentials,
        user_verification: response.user_verification,
        timeout: response.timeout,
    };

    Ok(HttpResponse::Ok().json(start_response))
}

/// Finish authentication process
pub async fn finish_authentication(
    req: web::Json<AuthenticationFinishRequest>,
    fido_service: web::Data<FidoService>,
) -> Result<HttpResponse> {
    let result = fido_service
        .finish_authentication(&req.credential, &req.session_id)
        .await?;

    let response = AuthenticationFinishResponse {
        user_id: result.user_id.to_string(),
        session_token: result.session_token,
    };

    Ok(HttpResponse::Ok().json(response))
}