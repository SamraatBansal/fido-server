//! Storage abstraction and implementations

use crate::error::{AppError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage trait for different storage backends
#[async_trait]
pub trait Storage: Send + Sync {
    /// Store a user
    async fn store_user(&self, user: &StoredUser) -> Result<()>;

    /// Get a user by ID
    async fn get_user(&self, user_id: &str) -> Result<Option<StoredUser>>;

    /// Get a user by username
    async fn get_user_by_username(&self, username: &str) -> Result<Option<StoredUser>>;

    /// Update a user
    async fn update_user(&self, user: &StoredUser) -> Result<()>;

    /// Delete a user
    async fn delete_user(&self, user_id: &str) -> Result<()>;

    /// Store a credential mapping
    async fn store_mapping(&self, mapping: &CredentialMapping) -> Result<()>;

    /// Get a mapping by ID
    async fn get_mapping(&self, mapping_id: &str) -> Result<Option<CredentialMapping>>;

    /// Get mappings by credential ID
    async fn get_mappings_by_credential(
        &self,
        credential_id: &str,
    ) -> Result<Vec<CredentialMapping>>;

    /// Delete a mapping
    async fn delete_mapping(&self, mapping_id: &str) -> Result<()>;
}

/// Stored user representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub credentials: Vec<StoredCredential>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Stored credential representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub user_id: String,
    pub credential_data: String, // Serialized Passkey
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Credential mapping for external ID binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMapping {
    pub id: String,
    pub credential_id: String,
    pub external_id: String,
    pub external_type: String, // "email", "account_id", etc.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// In-memory storage implementation
#[derive(Debug, Default)]
pub struct MemoryStorage {
    users: std::sync::RwLock<HashMap<String, StoredUser>>,
    username_index: std::sync::RwLock<HashMap<String, String>>, // username -> user_id
    mappings: std::sync::RwLock<HashMap<String, CredentialMapping>>,
    credential_mappings: std::sync::RwLock<HashMap<String, Vec<String>>>, // credential_id -> vec[mapping_id]
}

impl MemoryStorage {
    /// Create a new in-memory storage instance
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn store_user(&self, user: &StoredUser) -> Result<()> {
        let mut users = self.users.write().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire write lock for users: {}", e))
        })?;
        let mut username_index = self.username_index.write().map_err(|e| {
            AppError::InternalError(format!(
                "Failed to acquire write lock for username index: {}",
                e
            ))
        })?;

        users.insert(user.id.clone(), user.clone());
        username_index.insert(user.username.clone(), user.id.clone());

        Ok(())
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<StoredUser>> {
        let users = self.users.read().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire read lock for users: {}", e))
        })?;

        Ok(users.get(user_id).cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<StoredUser>> {
        let username_index = self.username_index.read().map_err(|e| {
            AppError::InternalError(format!(
                "Failed to acquire read lock for username index: {}",
                e
            ))
        })?;
        let users = self.users.read().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire read lock for users: {}", e))
        })?;

        if let Some(user_id) = username_index.get(username) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_user(&self, user: &StoredUser) -> Result<()> {
        let mut users = self.users.write().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire write lock for users: {}", e))
        })?;

        users.insert(user.id.clone(), user.clone());

        Ok(())
    }

    async fn delete_user(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire write lock for users: {}", e))
        })?;
        let mut username_index = self.username_index.write().map_err(|e| {
            AppError::InternalError(format!(
                "Failed to acquire write lock for username index: {}",
                e
            ))
        })?;

        if let Some(user) = users.remove(user_id) {
            username_index.remove(&user.username);
        }

        Ok(())
    }

    async fn store_mapping(&self, mapping: &CredentialMapping) -> Result<()> {
        let mut mappings = self.mappings.write().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire write lock for mappings: {}", e))
        })?;
        let mut credential_mappings = self.credential_mappings.write().map_err(|e| {
            AppError::InternalError(format!(
                "Failed to acquire write lock for credential mappings: {}",
                e
            ))
        })?;

        mappings.insert(mapping.id.clone(), mapping.clone());

        credential_mappings
            .entry(mapping.credential_id.clone())
            .or_insert_with(Vec::new)
            .push(mapping.id.clone());

        Ok(())
    }

    async fn get_mapping(&self, mapping_id: &str) -> Result<Option<CredentialMapping>> {
        let mappings = self.mappings.read().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire read lock for mappings: {}", e))
        })?;

        Ok(mappings.get(mapping_id).cloned())
    }

    async fn get_mappings_by_credential(
        &self,
        credential_id: &str,
    ) -> Result<Vec<CredentialMapping>> {
        let mappings = self.mappings.read().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire read lock for mappings: {}", e))
        })?;
        let credential_mappings = self.credential_mappings.read().map_err(|e| {
            AppError::InternalError(format!(
                "Failed to acquire read lock for credential mappings: {}",
                e
            ))
        })?;

        if let Some(mapping_ids) = credential_mappings.get(credential_id) {
            let mut result = Vec::new();
            for mapping_id in mapping_ids {
                if let Some(mapping) = mappings.get(mapping_id) {
                    result.push(mapping.clone());
                }
            }
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }

    async fn delete_mapping(&self, mapping_id: &str) -> Result<()> {
        let mut mappings = self.mappings.write().map_err(|e| {
            AppError::InternalError(format!("Failed to acquire write lock for mappings: {}", e))
        })?;
        let mut credential_mappings = self.credential_mappings.write().map_err(|e| {
            AppError::InternalError(format!(
                "Failed to acquire write lock for credential mappings: {}",
                e
            ))
        })?;

        if let Some(mapping) = mappings.remove(mapping_id) {
            if let Some(mapping_ids) = credential_mappings.get_mut(&mapping.credential_id) {
                mapping_ids.retain(|id| id != mapping_id);
                if mapping_ids.is_empty() {
                    credential_mappings.remove(&mapping.credential_id);
                }
            }
        }

        Ok(())
    }
}
