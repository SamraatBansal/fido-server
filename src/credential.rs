use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    storage::{Credential, Storage},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct RevokeCredentialRequest {
    credential_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCredentialRequest {
    credential_id: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    id: Uuid,
    credential_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct CredentialsListResponse {
    credentials: Vec<CredentialResponse>,
}

impl From<Credential> for CredentialResponse {
    fn from(credential: Credential) -> Self {
        Self {
            id: credential.id,
            credential_id: credential.credential_id,
            created_at: credential.created_at,
            last_used_at: credential.last_used_at,
            is_active: credential.is_active,
        }
    }
}

pub async fn list_credentials(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<CredentialsListResponse>, AppError> {
    let credentials = state.storage.get_credentials_by_user(&user_id).await?;
    
    let credential_responses: Vec<CredentialResponse> = credentials
        .into_iter()
        .map(CredentialResponse::from)
        .collect();

    Ok(Json(CredentialsListResponse {
        credentials: credential_responses,
    }))
}

pub async fn revoke_credential(
    State(state): State<AppState>,
    Json(request): Json<RevokeCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.storage.revoke_credential(&request.credential_id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Credential revoked successfully"
    })))
}

pub async fn update_credential(
    State(state): State<AppState>,
    Json(request): Json<UpdateCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let credential = state.storage.get_credential_by_id(&request.credential_id).await?
        .ok_or(AppError::CredentialNotFound)?;

    state.storage.update_credential_last_used(&request.credential_id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Credential updated successfully",
        "credential_id": request.credential_id
    })))
}