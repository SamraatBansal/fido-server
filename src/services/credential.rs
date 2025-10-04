//! Credential management service

use std::sync::Arc;
use uuid::Uuid;

use crate::db::models::Credential;
use crate::db::repositories::CredentialRepository;
use crate::error::{AppError, Result};

pub struct CredentialService {
    credential_repo: Arc<dyn CredentialRepository>,
}

impl CredentialService {
    pub fn new(credential_repo: Arc<dyn CredentialRepository>) -> Self {
        Self { credential_repo }
    }

    /// Get all credentials for a user
    pub async fn get_user_credentials(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        self.credential_repo.find_by_user_id(user_id).await
    }

    /// Get credential by ID
    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        self.credential_repo.find_by_credential_id(credential_id).await
    }

    /// Delete a credential
    pub async fn delete_credential(&self, credential_id: &str, user_id: &Uuid) -> Result<()> {
        // Parse credential ID as UUID (assuming we store UUID as credential ID)
        let cred_uuid = Uuid::parse_str(credential_id)
            .map_err(|_| AppError::InvalidRequest("Invalid credential ID format".to_string()))?;

        self.credential_repo
            .delete_credential(&cred_uuid, user_id)
            .await
    }

    /// Update credential sign count
    pub async fn update_sign_count(&self, credential_id: &[u8], count: i64) -> Result<()> {
        // Find credential first to get UUID
        let credential = self
            .credential_repo
            .find_by_credential_id(credential_id)
            .await?
            .ok_or(AppError::InvalidCredential("Credential not found".to_string()))?;

        self.credential_repo.update_sign_count(&credential.id, count).await
    }

    /// Update last used timestamp
    pub async fn update_last_used(&self, credential_id: &[u8]) -> Result<()> {
        // Find credential first to get UUID
        let credential = self
            .credential_repo
            .find_by_credential_id(credential_id)
            .await?
            .ok_or(AppError::InvalidCredential("Credential not found".to_string()))?;

        self.credential_repo.update_last_used(&credential.id).await
    }
}