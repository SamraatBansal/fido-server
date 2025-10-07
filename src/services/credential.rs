//! Credential management service

use async_trait::async_trait;
use crate::error::{AppError, Result};
use crate::schema::credential::Credential;
use uuid::Uuid;

/// Credential repository trait for dependency injection
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    /// Create a new credential
    async fn create(&self, credential: &Credential) -> Result<()>;
    
    /// Find a credential by ID
    async fn find_by_id(&self, id: &[u8]) -> Result<Option<Credential>>;
    
    /// Find all credentials for a user
    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
    
    /// Update the signature counter
    async fn update_sign_count(&self, id: &[u8], count: u64) -> Result<()>;
    
    /// Update credential usage information
    async fn update_usage(&self, id: &[u8], new_sign_count: u64) -> Result<()>;
    
    /// Delete a credential
    async fn delete(&self, id: &[u8]) -> Result<()>;
    
    /// Check if a credential ID exists for a user
    async fn exists_for_user(&self, user_id: &Uuid, credential_id: &[u8]) -> Result<bool>;
}

/// In-memory credential repository for testing and development
#[derive(Debug, Default)]
pub struct InMemoryCredentialRepository {
    credentials: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Credential>>>,
}

impl InMemoryCredentialRepository {
    /// Create a new in-memory credential repository
    pub fn new() -> Self {
        Self::default()
    }

    /// Helper function to convert credential ID to string key
    fn credential_id_to_key(id: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id)
    }
}

#[async_trait]
impl CredentialRepository for InMemoryCredentialRepository {
    async fn create(&self, credential: &Credential) -> Result<()> {
        // Validate credential before storing
        credential.validate().map_err(|e| AppError::ValidationError(e))?;

        let mut credentials = self.credentials.write().await;
        let key = Self::credential_id_to_key(&credential.id);
        
        // Check for duplicate
        if credentials.contains_key(&key) {
            return Err(AppError::BadRequest("Credential ID already exists".to_string()));
        }
        
        credentials.insert(key, credential.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &[u8]) -> Result<Option<Credential>> {
        let credentials = self.credentials.read().await;
        let key = Self::credential_id_to_key(id);
        Ok(credentials.get(&key).cloned())
    }

    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        let credentials = self.credentials.read().await;
        let user_credentials = credentials
            .values()
            .filter(|cred| cred.user_id == *user_id)
            .cloned()
            .collect();
        Ok(user_credentials)
    }

    async fn update_sign_count(&self, id: &[u8], count: u64) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        let key = Self::credential_id_to_key(id);
        
        if let Some(credential) = credentials.get_mut(&key) {
            credential.sign_count = count;
            Ok(())
        } else {
            Err(AppError::NotFound("Credential not found".to_string()))
        }
    }

    async fn update_usage(&self, id: &[u8], new_sign_count: u64) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        let key = Self::credential_id_to_key(id);
        
        if let Some(credential) = credentials.get_mut(&key) {
            // Check for counter regression
            if credential.has_counter_regression(new_sign_count) {
                return Err(AppError::BadRequest("Potential credential cloning detected - signature counter regression".to_string()));
            }
            
            credential.update_usage(new_sign_count);
            Ok(())
        } else {
            Err(AppError::NotFound("Credential not found".to_string()))
        }
    }

    async fn delete(&self, id: &[u8]) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        let key = Self::credential_id_to_key(id);
        
        if credentials.remove(&key).is_some() {
            Ok(())
        } else {
            Err(AppError::NotFound("Credential not found".to_string()))
        }
    }

    async fn exists_for_user(&self, user_id: &Uuid, credential_id: &[u8]) -> Result<bool> {
        let credentials = self.credentials.read().await;
        let key = Self::credential_id_to_key(credential_id);
        
        if let Some(credential) = credentials.get(&key) {
            Ok(credential.user_id == *user_id)
        } else {
            Ok(false)
        }
    }
}

/// Credential service
pub struct CredentialService {
    repository: InMemoryCredentialRepository,
}

impl CredentialService {
    /// Create a new credential service
    pub fn new(repository: InMemoryCredentialRepository) -> Self {
        Self { repository }
    }

    /// Register a new credential
    pub async fn register_credential(&self, credential: Credential) -> Result<()> {
        // Validate the credential
        credential.validate().map_err(|e| AppError::ValidationError(e))?;

        // Check if credential already exists for this user
        let exists = self.repository.exists_for_user(&credential.user_id, &credential.id).await?;
        if exists {
            return Err(AppError::BadRequest("Credential already registered for this user".to_string()));
        }

        // Store the credential
        self.repository.create(&credential).await
    }

    /// Get a credential by ID
    pub async fn get_credential(&self, id: &[u8]) -> Result<Option<Credential>> {
        self.repository.find_by_id(id).await
    }

    /// Get all credentials for a user
    pub async fn get_user_credentials(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        self.repository.find_by_user_id(user_id).await
    }

    /// Authenticate with a credential
    pub async fn authenticate_credential(&self, credential_id: &[u8], new_sign_count: u64) -> Result<Credential> {
        // Get the credential
        let mut credential = self.repository.find_by_id(credential_id).await?
            .ok_or_else(|| AppError::NotFound("Credential not found".to_string()))?;

        // Check for counter regression (potential cloning)
        if credential.has_counter_regression(new_sign_count) {
            return Err(AppError::BadRequest("Potential credential cloning detected - signature counter regression".to_string()));
        }

        // Update usage information
        self.repository.update_usage(credential_id, new_sign_count).await?;

        // Get updated credential
        credential = self.repository.find_by_id(credential_id).await?
            .ok_or_else(|| AppError::NotFound("Credential not found".to_string()))?;

        Ok(credential)
    }

    /// Delete a credential
    pub async fn delete_credential(&self, id: &[u8]) -> Result<()> {
        self.repository.delete(id).await
    }

    /// Delete all credentials for a user
    pub async fn delete_user_credentials(&self, user_id: &Uuid) -> Result<()> {
        let credentials = self.repository.find_by_user_id(user_id).await?;
        
        for credential in credentials {
            self.repository.delete(&credential.id).await?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_credential_repository() {
        let repo = InMemoryCredentialRepository::new();
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        // Create credential
        repo.create(&credential).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(&credential.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap(), credential);

        // Find by user ID
        let user_creds = repo.find_by_user_id(&user_id).await.unwrap();
        assert_eq!(user_creds.len(), 1);
        assert_eq!(user_creds[0], credential);

        // Update usage
        repo.update_usage(&credential.id, 42).await.unwrap();
        let updated = repo.find_by_id(&credential.id).await.unwrap().unwrap();
        assert_eq!(updated.sign_count, 42);
        assert!(updated.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_credential_validation() {
        let repo = InMemoryCredentialRepository::new();
        let user_id = Uuid::new_v4();

        // Test invalid credential (empty ID)
        let invalid_credential = Credential::new(
            vec![],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        let result = repo.create(&invalid_credential).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_duplicate_credential() {
        let repo = InMemoryCredentialRepository::new();
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        // Create first credential
        repo.create(&credential).await.unwrap();

        // Try to create duplicate
        let result = repo.create(&credential).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_counter_regression_detection() {
        let repo = InMemoryCredentialRepository::new();
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        repo.create(&credential).await.unwrap();

        // Update to counter 10
        repo.update_usage(&credential.id, 10).await.unwrap();

        // Try to update to counter 5 (regression)
        let result = repo.update_usage(&credential.id, 5).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_credential_service_register() {
        let repo = Box::new(InMemoryCredentialRepository::new());
        let service = CredentialService::new(repo);
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        // Register credential
        service.register_credential(credential.clone()).await.unwrap();

        // Verify it was stored
        let retrieved = service.get_credential(&credential.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), credential);
    }

    #[tokio::test]
    async fn test_credential_service_authenticate() {
        let repo = Box::new(InMemoryCredentialRepository::new());
        let service = CredentialService::new(repo);
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        // Register credential
        service.register_credential(credential.clone()).await.unwrap();

        // Authenticate with higher counter
        let auth_result = service.authenticate_credential(&credential.id, 15).await.unwrap();
        assert_eq!(auth_result.sign_count, 15);
        assert!(auth_result.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_credential_service_authenticate_regression() {
        let repo = Box::new(InMemoryCredentialRepository::new());
        let service = CredentialService::new(repo);
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        // Register credential
        service.register_credential(credential.clone()).await.unwrap();

        // First authenticate with counter 10
        service.authenticate_credential(&credential.id, 10).await.unwrap();

        // Try to authenticate with counter 5 (regression)
        let result = service.authenticate_credential(&credential.id, 5).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_credential_service_delete_user_credentials() {
        let repo = Box::new(InMemoryCredentialRepository::new());
        let service = CredentialService::new(repo);
        let user_id = Uuid::new_v4();

        // Create multiple credentials for the user
        let cred1 = Credential::new(
            vec![1, 2, 3, 4],
            user_id,
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        let cred2 = Credential::new(
            vec![5, 6, 7, 8],
            user_id,
            vec![9, 10, 11, 12],
            "fido-u2f".to_string(),
            vec!["nfc".to_string()],
        );

        service.register_credential(cred1).await.unwrap();
        service.register_credential(cred2).await.unwrap();

        // Verify both exist
        let user_creds = service.get_user_credentials(&user_id).await.unwrap();
        assert_eq!(user_creds.len(), 2);

        // Delete all user credentials
        service.delete_user_credentials(&user_id).await.unwrap();

        // Verify they're gone
        let user_creds = service.get_user_credentials(&user_id).await.unwrap();
        assert_eq!(user_creds.len(), 0);
    }
}