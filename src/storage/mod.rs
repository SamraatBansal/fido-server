pub mod memory;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::error::AppResult;
use crate::models::{User, StoredCredential, StoredChallenge};

#[async_trait]
pub trait Storage: Send + Sync {
    // User operations
    async fn create_user(&self, user: User) -> AppResult<User>;
    async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>>;
    async fn get_user_by_id(&self, user_id: Uuid) -> AppResult<Option<User>>;
    
    // Credential operations
    async fn create_credential(&self, credential: StoredCredential) -> AppResult<StoredCredential>;
    async fn get_credentials_by_user_id(&self, user_id: Uuid) -> AppResult<Vec<StoredCredential>>;
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> AppResult<Option<StoredCredential>>;
    async fn update_credential_last_used(&self, credential_id: &[u8], last_used: DateTime<Utc>) -> AppResult<()>;
    
    // Challenge operations
    async fn store_challenge(&self, challenge: StoredChallenge) -> AppResult<()>;
    async fn get_challenge(&self, challenge_id: &str) -> AppResult<Option<StoredChallenge>>;
    async fn remove_challenge(&self, challenge_id: &str) -> AppResult<()>;
    async fn cleanup_expired_challenges(&self) -> AppResult<()>;
}