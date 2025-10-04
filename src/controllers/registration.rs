//! Registration controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use webauthn_rs::prelude::*;

use crate::{
    error::AppError,
    schema::requests::{RegistrationFinishRequest, RegistrationStartRequest},
    schema::responses::{RegistrationStartResponse, RegistrationFinishResponse},
    services::{FidoService, UserService},
};

/// Start registration process
pub async fn start_registration(
    req: web::Json<RegistrationStartRequest>,
    fido_service: web::Data<FidoService>,
    user_service: web::Data<UserService>,
) -> Result<HttpResponse> {
    let user = user_service
        .get_or_create_user(&req.username, &req.display_name)
        .await?;

    let response = fido_service
        .start_registration(&user, req.user_verification)
        .await?;

    let start_response = RegistrationStartResponse {
        challenge: response.challenge.as_str().to_string(),
        user: user.into(),
        pub_key_cred_params: response.pub_key_cred_params,
        timeout: response.timeout,
        attestation: response.attestation,
        authenticator_selection: response.authenticator_selection,
    };

    Ok(HttpResponse::Ok().json(start_response))
}

/// Finish registration process
pub async fn finish_registration(
    req: web::Json<RegistrationFinishRequest>,
    fido_service: web::Data<FidoService>,
) -> Result<HttpResponse> {
    let result = fido_service
        .finish_registration(&req.credential, &req.session_id)
        .await?;

    let response = RegistrationFinishResponse {
        credential_id: result.credential_id,
        user_id: result.user_id.to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
}