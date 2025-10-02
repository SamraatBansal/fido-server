use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    storage::{Mapping, Storage},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateMappingRequest {
    credential_id: String,
    external_id: String,
    external_type: String,
}

#[derive(Debug, Serialize)]
pub struct MappingResponse {
    id: Uuid,
    credential_id: Uuid,
    external_id: String,
    external_type: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<Mapping> for MappingResponse {
    fn from(mapping: Mapping) -> Self {
        Self {
            id: mapping.id,
            credential_id: mapping.credential_id,
            external_id: mapping.external_id,
            external_type: mapping.external_type,
            created_at: mapping.created_at,
        }
    }
}

pub async fn create_mapping(
    State(state): State<AppState>,
    Json(request): Json<CreateMappingRequest>,
) -> Result<Json<MappingResponse>, AppError> {
    let credential = state.storage.get_credential_by_id(&request.credential_id).await?
        .ok_or(AppError::CredentialNotFound)?;

    let mapping = state.storage.create_mapping(
        credential.id,
        &request.external_id,
        &request.external_type,
    ).await?;

    Ok(Json(MappingResponse::from(mapping)))
}

pub async fn get_mapping(
    State(state): State<AppState>,
    Path(mapping_id): Path<Uuid>,
) -> Result<Json<MappingResponse>, AppError> {
    let mapping = state.storage.get_mapping_by_id(mapping_id).await?
        .ok_or(AppError::CredentialNotFound)?;

    Ok(Json(MappingResponse::from(mapping)))
}

pub async fn delete_mapping(
    State(state): State<AppState>,
    Path(mapping_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.storage.delete_mapping(mapping_id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Mapping deleted successfully"
    })))
}

pub async fn get_mapping_by_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> Result<Json<Vec<MappingResponse>>, AppError> {
    let mappings = state.storage.get_mapping_by_credential(&credential_id).await?;
    
    let mapping_responses: Vec<MappingResponse> = mappings
        .into_iter()
        .map(MappingResponse::from)
        .collect();

    Ok(Json(mapping_responses))
}