//! Storage service implementations

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Represents a user's WebAuthn credential
#[derive(Debug, Clone)]
pub struct UserCredential {
    /// Unique identifier for the credential
    pub credential_id: Vec<u8>,
    /// Public key associated with the credential
    pub public_key: Vec<u8>,
    /// User ID this credential belongs to
    pub user_id: String,
    /// Number of times this credential has been used for authentication
    pub sign_count: u32,
}

/// Trait for storage services that handle WebAuthn credentials
#[async_trait]
pub trait StorageService: Send + Sync {
    /// Stores a new credential in the storage
    async fn store_credential(&self, credential: UserCredential) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Retrieves a credential by its ID
    async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<UserCredential>, Box<dyn std::error::Error + Send + Sync>>;
    /// Retrieves all credentials for a given user
    async fn get_user_credentials(&self, user_id: &str) -> Result<Vec<UserCredential>, Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory storage implementation for testing and development
pub struct InMemoryStorage {
    credentials: Arc<RwLock<HashMap<Vec<u8>, UserCredential>>>,
    user_credentials: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
}

impl InMemoryStorage {
    /// Creates a new in-memory storage instance
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            user_credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageService for InMemoryStorage {
    async fn store_credential(&self, credential: UserCredential) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let credential_id = credential.credential_id.clone();
        let user_id = credential.user_id.clone();
        
        // Store credential by ID
        self.credentials.write().await.insert(credential_id.clone(), credential);
        
        // Add to user's credential list
        let mut user_creds = self.user_credentials.write().await;
        user_creds.entry(user_id).or_insert_with(Vec::new).push(credential_id);
        
        Ok(())
    }

    async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<UserCredential>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.credentials.read().await.get(credential_id).cloned())
    }

    async fn get_user_credentials(&self, user_id: &str) -> Result<Vec<UserCredential>, Box<dyn std::error::Error + Send + Sync>> {
        let user_creds = self.user_credentials.read().await;
        let credentials = self.credentials.read().await;
        
        if let Some(credential_ids) = user_creds.get(user_id) {
            let mut result = Vec::new();
            for cred_id in credential_ids {
                if let Some(credential) = credentials.get(cred_id) {
                    result.push(credential.clone());
                }
            }
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }
}

/// PostgreSQL storage implementation for production use
pub struct PostgresStorage {
    // TODO: Implement PostgreSQL storage
}

impl PostgresStorage {
    /// Creates a new PostgreSQL storage instance
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl StorageService for PostgresStorage {
    async fn store_credential(&self, _credential: UserCredential) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        todo!("Implement PostgreSQL storage")
    }

    async fn get_credential(&self, _credential_id: &[u8]) -> Result<Option<UserCredential>, Box<dyn std::error::Error + Send + Sync>> {
        todo!("Implement PostgreSQL storage")
    }

    async fn get_user_credentials(&self, _user_id: &str) -> Result<Vec<UserCredential>, Box<dyn std::error::Error + Send + Sync>> {
        todo!("Implement PostgreSQL storage")
    }
}