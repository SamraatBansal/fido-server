//! Mock repository implementations for testing

use crate::domain::repositories::*;
use crate::error::{AppError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct MockUserRepository {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl MockUserRepository {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let users = self.users.read().await;
        Ok(users.values().find(|u| u.username == username).cloned())
    }

    async fn create_user(&self, user: &User) -> Result<()> {
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user.clone());
        Ok(())
    }

    async fn update_user(&self, user: &User) -> Result<()> {
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user.clone());
        Ok(())
    }
}

pub struct MockCredentialRepository {
    credentials: Arc<RwLock<HashMap<String, Credential>>>,
}

impl MockCredentialRepository {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl CredentialRepository for MockCredentialRepository {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<Credential>> {
        let credentials = self.credentials.read().await;
        Ok(credentials
            .values()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn find_by_credential_id(&self, credential_id: &str) -> Result<Option<Credential>> {
        let credentials = self.credentials.read().await;
        Ok(credentials
            .values()
            .find(|c| c.credential_id == credential_id)
            .cloned())
    }

    async fn save_credential(&self, credential: &Credential) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        credentials.insert(credential.id.clone(), credential.clone());
        Ok(())
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        credentials.retain(|_, c| c.credential_id != credential_id);
        Ok(())
    }
}

pub struct MockChallengeRepository {
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
}

impl MockChallengeRepository {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ChallengeRepository for MockChallengeRepository {
    async fn save_challenge(&self, challenge: &Challenge) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.id.clone(), challenge.clone());
        Ok(())
    }

    async fn find_and_delete_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>> {
        let mut challenges = self.challenges.write().await;
        Ok(challenges.remove(challenge_id))
    }

    async fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        let now = chrono::Utc::now();
        challenges.retain(|_, c| c.expires_at > now);
        Ok(())
    }
}