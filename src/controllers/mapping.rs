//! Mapping controller for credential to external ID binding

use crate::error::{AppError, Result};
use crate::services::{CredentialMapping, Storage};
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Create mapping request
#[derive(Debug, Deserialize)]
pub struct CreateMappingRequest {
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
}

/// Create mapping response
#[derive(Debug, Serialize)]
pub struct CreateMappingResponse {
    pub id: String,
    pub success: bool,
}

/// Mapping response
#[derive(Debug, Serialize)]
pub struct MappingResponse {
    pub id: String,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Mapping controller
pub struct MappingController {
    storage: Arc<dyn Storage>,
}

impl MappingController {
    /// Create a new mapping controller
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// Create a new mapping
    pub async fn create_mapping(
        &self,
        req: web::Json<CreateMappingRequest>,
    ) -> Result<HttpResponse> {
        // Validate input
        if req.credential_id.trim().is_empty() {
            return Err(AppError::ValidationError(
                "Credential ID cannot be empty".to_string(),
            ));
        }

        if req.external_id.trim().is_empty() {
            return Err(AppError::ValidationError(
                "External ID cannot be empty".to_string(),
            ));
        }

        if req.external_type.trim().is_empty() {
            return Err(AppError::ValidationError(
                "External type cannot be empty".to_string(),
            ));
        }

        // Create mapping
        let mapping = CredentialMapping {
            id: Uuid::new_v4().to_string(),
            credential_id: req.credential_id.clone(),
            external_id: req.external_id.clone(),
            external_type: req.external_type.clone(),
            created_at: chrono::Utc::now(),
        };

        // Store mapping
        self.storage.store_mapping(&mapping).await?;

        Ok(HttpResponse::Created().json(CreateMappingResponse {
            id: mapping.id.clone(),
            success: true,
        }))
    }

    /// Get mapping by ID
    pub async fn get_mapping(&self, path: web::Path<String>) -> Result<HttpResponse> {
        let mapping_id = path.into_inner();

        let mapping = self
            .storage
            .get_mapping(&mapping_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Mapping not found".to_string()))?;

        Ok(HttpResponse::Ok().json(MappingResponse {
            id: mapping.id,
            credential_id: mapping.credential_id,
            external_id: mapping.external_id,
            external_type: mapping.external_type,
            created_at: mapping.created_at,
        }))
    }

    /// Get mappings by credential ID
    pub async fn get_mappings_by_credential(
        &self,
        path: web::Path<String>,
    ) -> Result<HttpResponse> {
        let credential_id = path.into_inner();

        let mappings = self
            .storage
            .get_mappings_by_credential(&credential_id)
            .await?;

        let response: Vec<MappingResponse> = mappings
            .into_iter()
            .map(|m| MappingResponse {
                id: m.id,
                credential_id: m.credential_id,
                external_id: m.external_id,
                external_type: m.external_type,
                created_at: m.created_at,
            })
            .collect();

        Ok(HttpResponse::Ok().json(response))
    }

    /// Delete mapping
    pub async fn delete_mapping(&self, path: web::Path<String>) -> Result<HttpResponse> {
        let mapping_id = path.into_inner();

        // Check if mapping exists
        let _mapping = self
            .storage
            .get_mapping(&mapping_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Mapping not found".to_string()))?;

        // Delete mapping
        self.storage.delete_mapping(&mapping_id).await?;

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true
        })))
    }
}
