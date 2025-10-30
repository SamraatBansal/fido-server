//! Credential service implementation

use std::sync::Arc;
use crate::db::repositories::CredentialRepository;
use crate::models::Credential;
use crate::error::{AppError, Result};

/// Credential service
pub struct CredentialService {
    credential_repo: Arc<dyn CredentialRepository>,
}

impl CredentialService {
    /// Create a new credential service
    pub fn new(credential_repo: Arc<dyn CredentialRepository>) -> Self {
        Self { credential_repo }
    }

    /// Get credential by ID
    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        self.credential_repo.get_credential_by_id(credential_id).await
    }

    /// Get credentials for user
    pub async fn get_credentials_for_user(&self, user_id: uuid::Uuid) -> Result<Vec<Credential>> {
        self.credential_repo.get_credentials_for_user(user_id).await
    }

    /// Create credential
    pub async fn create_credential(&self, credential: &Credential) -> Result<()> {
        // Check if credential already exists
        if self.credential_repo.get_credential_by_id(&credential.credential_id).await?.is_some() {
            return Err(AppError::InvalidInput("Credential already exists".to_string()));
        }

        self.credential_repo.create_credential(credential).await
    }

    /// Update credential
    pub async fn update_credential(&self, credential: &Credential) -> Result<()> {
        // Check if credential exists
        if self.credential_repo.get_credential_by_id(&credential.credential_id).await?.is_none() {
            return Err(AppError::CredentialNotFound("Credential not found".to_string()));
        }

        self.credential_repo.update_credential(credential).await
    }

    /// Delete credential
    pub async fn delete_credential(&self, credential_id: &[u8]) -> Result<()> {
        // Check if credential exists
        if self.credential_repo.get_credential_by_id(credential_id).await?.is_none() {
            return Err(AppError::CredentialNotFound("Credential not found".to_string()));
        }

        self.credential_repo.delete_credential(credential_id).await
    }
}