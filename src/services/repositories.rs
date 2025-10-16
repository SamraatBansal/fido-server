//! Repository traits for dependency injection

use async_trait::async_trait;
use uuid::Uuid;
use crate::db::models::{User, Credential, Challenge, NewUser, NewCredential, NewChallenge};
use crate::error::Result;

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn create(&self, user: &NewUser) -> Result<User>;
    async fn update(&self, user: &User) -> Result<User>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

/// Credential repository trait
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>>;
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    async fn create(&self, credential: &NewCredential) -> Result<Credential>;
    async fn update_sign_count(&self, id: Uuid, count: i64) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

/// Challenge repository trait
#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn find_by_challenge(&self, challenge: &str) -> Result<Option<Challenge>>;
    async fn create(&self, challenge: &NewChallenge) -> Result<Challenge>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<()>;
}