//! Repository layer for data access

use async_trait::async_trait;
use crate::models::{User, Credential, Challenge, ChallengeType};
use crate::error::Result;
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<()>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>>;
    async fn update_user(&self, user: &User) -> Result<()>;
    async fn delete_user(&self, user_id: &Uuid) -> Result<()>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, credential: &Credential) -> Result<()>;
    async fn get_credential_by_id(&self, credential_id: &str) -> Result<Option<Credential>>;
    async fn get_credentials_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
    async fn update_credential(&self, credential: &Credential) -> Result<()>;
    async fn delete_credential(&self, credential_id: &str) -> Result<()>;
    async fn credential_exists(&self, credential_id: &str) -> Result<bool>;
}

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn create_challenge(&self, challenge: &Challenge) -> Result<()>;
    async fn get_challenge_by_hash(&self, challenge_hash: &[u8], user_id: Option<&Uuid>, challenge_type: &ChallengeType) -> Result<Option<Challenge>>;
    async fn mark_challenge_used(&self, challenge_id: &Uuid) -> Result<()>;
    async fn cleanup_expired_challenges(&self) -> Result<u64>; // Returns number of cleaned up challenges
}

pub mod credential_repo;
pub mod user_repo;
pub mod challenge_repo;

pub use credential_repo::CredentialRepositoryImpl;
pub use user_repo::UserRepositoryImpl;
pub use challenge_repo::ChallengeRepositoryImpl;