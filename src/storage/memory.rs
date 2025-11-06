use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{User, StoredCredential, StoredChallenge};
use crate::storage::Storage;

#[derive(Debug)]
pub struct MemoryStorage {
    users_by_id: Arc<DashMap<Uuid, User>>,
    users_by_username: Arc<DashMap<String, Uuid>>,
    credentials: Arc<DashMap<Uuid, Vec<StoredCredential>>>,
    credential_index: Arc<DashMap<String, (Uuid, usize)>>, // credential_id -> (user_id, index)
    challenges: Arc<DashMap<String, StoredChallenge>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            users_by_id: Arc::new(DashMap::new()),
            users_by_username: Arc::new(DashMap::new()),
            credentials: Arc::new(DashMap::new()),
            credential_index: Arc::new(DashMap::new()),
            challenges: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn create_user(&self, user: User) -> AppResult<User> {
        if self.users_by_username.contains_key(&user.username) {
            return Err(AppError::Validation {
                message: format!("Username '{}' already exists", user.username),
            });
        }
        
        self.users_by_username.insert(user.username.clone(), user.id);
        self.users_by_id.insert(user.id, user.clone());
        self.credentials.insert(user.id, Vec::new());
        
        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        if let Some(user_id) = self.users_by_username.get(username) {
            Ok(self.users_by_id.get(&user_id).map(|u| u.clone()))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_id(&self, user_id: Uuid) -> AppResult<Option<User>> {
        Ok(self.users_by_id.get(&user_id).map(|u| u.clone()))
    }

    async fn create_credential(&self, credential: StoredCredential) -> AppResult<StoredCredential> {
        let credential_id_hex = hex::encode(&credential.credential_id);
        
        // Check if credential already exists
        if self.credential_index.contains_key(&credential_id_hex) {
            return Err(AppError::Validation {
                message: "Credential already exists".to_string(),
            });
        }
        
        let mut user_credentials = self.credentials.entry(credential.user_id)
            .or_insert_with(Vec::new);
        
        let index = user_credentials.len();
        user_credentials.push(credential.clone());
        
        self.credential_index.insert(credential_id_hex, (credential.user_id, index));
        
        Ok(credential)
    }

    async fn get_credentials_by_user_id(&self, user_id: Uuid) -> AppResult<Vec<StoredCredential>> {
        Ok(self.credentials.get(&user_id)
            .map(|creds| creds.clone())
            .unwrap_or_default())
    }

    async fn get_credential_by_id(&self, credential_id: &[u8]) -> AppResult<Option<StoredCredential>> {
        let credential_id_hex = hex::encode(credential_id);
        
        if let Some(entry) = self.credential_index.get(&credential_id_hex) {
            let (user_id, index) = entry.value();
            if let Some(user_credentials) = self.credentials.get(user_id) {
                Ok(user_credentials.get(*index).cloned())
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn update_credential_last_used(&self, credential_id: &[u8], last_used: DateTime<Utc>) -> AppResult<()> {
        let credential_id_hex = hex::encode(credential_id);
        
        if let Some(entry) = self.credential_index.get(&credential_id_hex) {
            let (user_id, index) = entry.value();
            if let Some(mut user_credentials) = self.credentials.get_mut(user_id) {
                if let Some(credential) = user_credentials.get_mut(*index) {
                    credential.last_used_at = Some(last_used);
                }
            }
        }
        
        Ok(())
    }

    async fn store_challenge(&self, challenge: StoredChallenge) -> AppResult<()> {
        self.challenges.insert(challenge.id.clone(), challenge);
        Ok(())
    }

    async fn get_challenge(&self, challenge_id: &str) -> AppResult<Option<StoredChallenge>> {
        Ok(self.challenges.get(challenge_id).map(|c| c.clone()))
    }

    async fn remove_challenge(&self, challenge_id: &str) -> AppResult<()> {
        self.challenges.remove(challenge_id);
        Ok(())
    }

    async fn cleanup_expired_challenges(&self) -> AppResult<()> {
        let now = Utc::now();
        let expired_keys: Vec<String> = self.challenges
            .iter()
            .filter(|entry| entry.value().expires_at < now)
            .map(|entry| entry.key().clone())
            .collect();
        
        for key in expired_keys {
            self.challenges.remove(&key);
        }
        
        Ok(())
    }
}