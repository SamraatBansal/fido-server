use crate::error::{AppError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub challenge_data: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct MemoryStore {
    users: Arc<RwLock<HashMap<String, StoredUser>>>, // username -> user
    users_by_id: Arc<RwLock<HashMap<Uuid, StoredUser>>>, // user_id -> user
    credentials: Arc<RwLock<HashMap<String, Vec<StoredCredential>>>>, // username -> credentials
    credentials_by_id: Arc<RwLock<HashMap<Vec<u8>, StoredCredential>>>, // credential_id -> credential
    challenges: Arc<RwLock<HashMap<String, StoredChallenge>>>, // challenge_id -> challenge
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            users_by_id: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
            credentials_by_id: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // User operations
    pub fn create_user(&self, username: &str, display_name: &str, user_id: Vec<u8>) -> Result<StoredUser> {
        let mut users = self.users.write().unwrap();
        let mut users_by_id = self.users_by_id.write().unwrap();

        if users.contains_key(username) {
            return Err(AppError::UserAlreadyExists {
                username: username.to_string(),
            });
        }

        let user = StoredUser {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            user_id,
            created_at: Utc::now(),
        };

        users.insert(username.to_string(), user.clone());
        users_by_id.insert(user.id, user.clone());

        Ok(user)
    }

    pub fn get_user(&self, username: &str) -> Option<StoredUser> {
        let users = self.users.read().unwrap();
        users.get(username).cloned()
    }

    pub fn get_user_by_id(&self, user_id: Uuid) -> Option<StoredUser> {
        let users = self.users_by_id.read().unwrap();
        users.get(&user_id).cloned()
    }

    // Credential operations
    pub fn store_credential(&self, user_id: Uuid, username: &str, passkey: Passkey) -> Result<Uuid> {
        let mut credentials = self.credentials.write().unwrap();
        let mut credentials_by_id = self.credentials_by_id.write().unwrap();

        let credential_id = Uuid::new_v4();
        let stored_credential = StoredCredential {
            id: credential_id,
            user_id,
            credential_id: passkey.cred_id().to_vec(),
            passkey: passkey.clone(),
            created_at: Utc::now(),
            last_used_at: None,
        };

        credentials
            .entry(username.to_string())
            .or_default()
            .push(stored_credential.clone());

        credentials_by_id.insert(passkey.cred_id().to_vec(), stored_credential);

        Ok(credential_id)
    }

    pub fn get_credentials(&self, username: &str) -> Vec<StoredCredential> {
        let credentials = self.credentials.read().unwrap();
        credentials.get(username).cloned().unwrap_or_default()
    }

    pub fn get_credential_by_id(&self, credential_id: &[u8]) -> Option<StoredCredential> {
        let credentials = self.credentials_by_id.read().unwrap();
        credentials.get(credential_id).cloned()
    }

    pub fn update_credential_counter(&self, credential_id: &[u8], counter: u32) -> Result<()> {
        let mut credentials_by_id = self.credentials_by_id.write().unwrap();
        
        if let Some(mut credential) = credentials_by_id.get_mut(credential_id) {
            credential.last_used_at = Some(Utc::now());
            // Note: We can't easily update the counter in the passkey without reconstruction
            // For now, just update the last_used timestamp
        }

        Ok(())
    }

    // Challenge operations
    pub fn store_challenge(&self, challenge: StoredChallenge) -> Result<()> {
        let mut challenges = self.challenges.write().unwrap();
        challenges.insert(challenge.id.clone(), challenge);
        Ok(())
    }

    pub fn get_challenge(&self, challenge_id: &str) -> Option<StoredChallenge> {
        let challenges = self.challenges.read().unwrap();
        challenges.get(challenge_id).and_then(|c| {
            if c.expires_at > Utc::now() {
                Some(c.clone())
            } else {
                None
            }
        })
    }

    pub fn consume_challenge(&self, challenge_id: &str) -> Option<StoredChallenge> {
        let mut challenges = self.challenges.write().unwrap();
        challenges.remove(challenge_id).and_then(|c| {
            if c.expires_at > Utc::now() {
                Some(c)
            } else {
                None
            }
        })
    }

    pub fn cleanup_expired_challenges(&self) -> usize {
        let mut challenges = self.challenges.write().unwrap();
        let now = Utc::now();
        let initial_len = challenges.len();
        challenges.retain(|_, challenge| challenge.expires_at > now);
        initial_len - challenges.len()
    }
}