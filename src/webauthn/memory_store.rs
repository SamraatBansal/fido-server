//! In-memory implementations for testing

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{AppError, Result};
use crate::webauthn::service::{ChallengeStore, UserRepository, CredentialRepository, User, NewUser, Credential, NewCredential};

/// In-memory challenge store
#[derive(Debug, Clone)]
pub struct InMemoryChallengeStore {
    challenges: Arc<RwLock<HashMap<String, (String, DateTime<Utc>)>>>,
}

impl InMemoryChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn store_challenge(&self, challenge: &str, username: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.to_string(), (username.to_string(), expires_at));
        Ok(())
    }

    async fn validate_and_consume_challenge(&self, challenge: &str, username: &str) -> Result<bool> {
        let mut challenges = self.challenges.write().await;
        
        if let Some((stored_username, expires_at)) = challenges.remove(challenge) {
            if stored_username != username {
                return Ok(false);
            }
            
            if Utc::now() > expires_at {
                return Ok(false);
            }
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        let now = Utc::now();
        
        challenges.retain(|_, (_, expires_at)| *expires_at > now);
        
        Ok(())
    }
}

/// In-memory user repository
#[derive(Debug, Clone)]
pub struct InMemoryUserRepository {
    users: Arc<RwLock<HashMap<String, User>>>,
    username_index: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemoryUserRepository {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            username_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn create_user(&self, new_user: NewUser) -> Result<User> {
        let mut users = self.users.write().await;
        let mut username_index = self.username_index.write().await;
        
        // Check if username already exists
        if username_index.contains_key(&new_user.username) {
            return Err(AppError::BadRequest("Username already exists".to_string()));
        }
        
        let user = User {
            id: new_user.id,
            username: new_user.username,
            display_name: new_user.display_name,
            created_at: new_user.created_at,
            updated_at: Utc::now(),
        };
        
        username_index.insert(user.username.clone(), user.id.clone());
        users.insert(user.id.clone(), user.clone());
        
        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let username_index = self.username_index.read().await;
        let users = self.users.read().await;
        
        if let Some(user_id) = username_index.get(username) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update_user(&self, user: User) -> Result<User> {
        let mut users = self.users.write().await;
        
        let updated_user = User {
            updated_at: Utc::now(),
            ..user
        };
        
        users.insert(updated_user.id.clone(), updated_user.clone());
        
        Ok(updated_user)
    }

    async fn delete_user(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write().await;
        let mut username_index = self.username_index.write().await;
        
        if let Some(user) = users.remove(user_id) {
            username_index.remove(&user.username);
        }
        
        Ok(())
    }
}

/// In-memory credential repository
#[derive(Debug, Clone)]
pub struct InMemoryCredentialRepository {
    credentials: Arc<RwLock<HashMap<String, Credential>>>,
    user_credentials: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl InMemoryCredentialRepository {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            user_credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl CredentialRepository for InMemoryCredentialRepository {
    async fn store_credential(&self, new_credential: NewCredential) -> Result<Credential> {
        let mut credentials = self.credentials.write().await;
        let mut user_credentials = self.user_credentials.write().await;
        
        let credential = Credential {
            id: new_credential.id,
            user_id: new_credential.user_id,
            public_key: new_credential.public_key,
            sign_count: new_credential.sign_count,
            created_at: new_credential.created_at,
            attestation_format: new_credential.attestation_format,
            aaguid: new_credential.aaguid,
        };
        
        // Add to credentials map
        credentials.insert(credential.id.clone(), credential.clone());
        
        // Add to user credentials index
        user_credentials
            .entry(credential.user_id.clone())
            .or_insert_with(Vec::new)
            .push(credential.id.clone());
        
        Ok(credential)
    }

    async fn get_credential_by_id(&self, id: &str) -> Result<Option<Credential>> {
        let credentials = self.credentials.read().await;
        Ok(credentials.get(id).cloned())
    }

    async fn get_credentials_by_user(&self, user_id: &str) -> Result<Vec<Credential>> {
        let credentials = self.credentials.read().await;
        let user_credentials = self.user_credentials.read().await;
        
        if let Some(credential_ids) = user_credentials.get(user_id) {
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

    async fn update_sign_count(&self, credential_id: &str, count: u32) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        
        if let Some(credential) = credentials.get_mut(credential_id) {
            credential.sign_count = count;
            Ok(())
        } else {
            Err(AppError::NotFound("Credential not found".to_string()))
        }
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let mut credentials = self.credentials.write().await;
        let mut user_credentials = self.user_credentials.write().await;
        
        if let Some(credential) = credentials.remove(credential_id) {
            if let Some(user_creds) = user_credentials.get_mut(&credential.user_id) {
                user_creds.retain(|id| id != credential_id);
            }
        }
        
        Ok(())
    }
}