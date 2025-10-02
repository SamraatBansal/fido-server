use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    error::AppError,
    storage::{Credential, Storage, User},
    webauthn::{WebAuthnService, WebAuthnUser},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    user_id: String,
    username: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    user_id: String,
    credential: PublicKeyCredential,
    state: RegistrationState,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    user_id: String,
    credential: PublicKeyCredential,
    state: AuthenticationState,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    challenge: String,
    user: Option<UserData>,
}

#[derive(Debug, Serialize)]
pub struct UserData {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    success: bool,
    credential_id: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationResponse {
    success: bool,
    user_id: String,
}

pub async fn registration_start(
    State(state): State<AppState>,
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<CreationChallengeResponse>, AppError> {
    let webauthn_service = WebAuthnService::new(
        &state.config.rp_id,
        &state.config.rp_name,
        &state.config.rp_origin,
    )?;

    let mut user = match state.storage.get_user_by_id(&request.user_id).await? {
        Some(user) => WebAuthnUser::new(
            user.user_id,
            user.username,
            user.display_name,
        ),
        None => {
            let new_user = state.storage.create_user(
                &request.user_id,
                &request.username,
                &request.display_name,
            ).await?;
            WebAuthnUser::new(
                new_user.user_id,
                new_user.username,
                new_user.display_name,
            )
        }
    };

    let credentials = state.storage.get_credentials_by_user(&request.user_id).await?;
    for cred in credentials {
        user.credentials.push(cred.passkey);
    }

    let challenge_response = webauthn_service.begin_registration(&user)?;

    Ok(Json(challenge_response))
}

pub async fn registration_finish(
    State(state): State<AppState>,
    Json(request): Json<RegistrationFinishRequest>,
) -> Result<Json<RegistrationResponse>, AppError> {
    let webauthn_service = WebAuthnService::new(
        &state.config.rp_id,
        &state.config.rp_name,
        &state.config.rp_origin,
    )?;

    let user = state.storage.get_user_by_id(&request.user_id).await?
        .ok_or(AppError::UserNotFound)?;

    let mut webauthn_user = WebAuthnUser::new(
        user.user_id,
        user.username,
        user.display_name,
    );

    let credentials = state.storage.get_credentials_by_user(&request.user_id).await?;
    for cred in credentials {
        webauthn_user.credentials.push(cred.passkey);
    }

    let passkey = webauthn_service.finish_registration(
        &mut webauthn_user,
        &request.credential,
        &request.state,
    )?;

    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&passkey.cred_id());
    
    state.storage.create_credential(
        user.id,
        &credential_id,
        &passkey,
    ).await?;

    Ok(Json(RegistrationResponse {
        success: true,
        credential_id,
    }))
}

pub async fn authentication_start(
    State(state): State<AppState>,
    Json(request): Json<AuthenticationStartRequest>,
) -> Result<Json<RequestChallengeResponse>, AppError> {
    let webauthn_service = WebAuthnService::new(
        &state.config.rp_id,
        &state.config.rp_name,
        &state.config.rp_origin,
    )?;

    let user = state.storage.get_user_by_id(&request.user_id).await?
        .ok_or(AppError::UserNotFound)?;

    let mut webauthn_user = WebAuthnUser::new(
        user.user_id,
        user.username,
        user.display_name,
    );

    let credentials = state.storage.get_credentials_by_user(&request.user_id).await?;
    for cred in credentials {
        webauthn_user.credentials.push(cred.passkey);
    }

    if webauthn_user.credentials.is_empty() {
        return Err(AppError::CredentialNotFound);
    }

    let challenge_response = webauthn_service.begin_authentication(&webauthn_user)?;

    Ok(Json(challenge_response))
}

pub async fn authentication_finish(
    State(state): State<AppState>,
    Json(request): Json<AuthenticationFinishRequest>,
) -> Result<Json<AuthenticationResponse>, AppError> {
    let webauthn_service = WebAuthnService::new(
        &state.config.rp_id,
        &state.config.rp_name,
        &state.config.rp_origin,
    )?;

    let user = state.storage.get_user_by_id(&request.user_id).await?
        .ok_or(AppError::UserNotFound)?;

    let mut webauthn_user = WebAuthnUser::new(
        user.user_id,
        user.username,
        user.display_name,
    );

    let credentials = state.storage.get_credentials_by_user(&request.user_id).await?;
    for cred in credentials {
        webauthn_user.credentials.push(cred.passkey);
    }

    let auth_result = webauthn_service.finish_authentication(
        &webauthn_user,
        &request.credential,
        &request.state,
    )?;

    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.cred_id());
    state.storage.update_credential_last_used(&credential_id).await?;

    Ok(Json(AuthenticationResponse {
        success: true,
        user_id: request.user_id,
    }))
}