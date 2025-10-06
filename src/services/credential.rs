//! Credential management service

use std::sync::Arc;
use uuid::Uuid;

use crate::db::models::{Credential, NewCredential};
use crate::db::repositories::CredentialRepository;
use crate::error::{AppError, Result};

/// Credential service for managing WebAuthn credentials
pub struct CredentialService {
    credential_repo: Arc<dyn CredentialRepository>,
}

impl CredentialService {
    /// Create a new credential service
    pub fn new(credential_repo: Arc<dyn CredentialRepository>) -> Self {
        Self { credential_repo }
    }

    /// Create a new credential
    pub async fn create_credential(&self, new_credential: &NewCredential) -> Result<Credential> {
        self.credential_repo.create_credential(new_credential).await
    }

    /// Get credentials by user ID
    pub async fn get_user_credentials(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        self.credential_repo.find_by_user_id(user_id).await
    }

    /// Get credential by credential ID
    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        self.credential_repo.find_by_credential_id(credential_id).await
    }

    /// Update credential metadata
    pub async fn update_credential(&self, credential: &Credential) -> Result<()> {
        self.credential_repo.update_credential(credential).await
    }

    /// Delete a credential
    pub async fn delete_credential(&self, credential_id: &Uuid, user_id: &Uuid) -> Result<()> {
        self.credential_repo.delete_credential(credential_id, user_id).await
    }
}