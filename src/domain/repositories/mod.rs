//! Repository traits for data access

use async_trait::async_trait;

use crate::error::Result;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn create_user(&self, user: &User) -> Result<()>;
    async fn update_user(&self, user: &User) -> Result<()>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<Credential>>;
    async fn find_by_credential_id(&self, credential_id: &str) -> Result<Option<Credential>>;
    async fn save_credential(&self, credential: &Credential) -> Result<()>;
    async fn delete_credential(&self, credential_id: &str) -> Result<()>;
}

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn save_challenge(&self, challenge: &Challenge) -> Result<()>;
    async fn find_and_delete_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>>;
    async fn cleanup_expired_challenges(&self) -> Result<()>;
}

// Domain entities
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: String,
    pub user_id: Option<String>,
    pub challenge: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub challenge_type: ChallengeType,
}

#[derive(Debug, Clone)]
pub enum ChallengeType {
    Registration,
    Authentication,
}