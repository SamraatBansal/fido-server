//! In-memory storage for testing and development

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_id: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>, // Serialized passkey data
    pub counter: i64,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryChallenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryStorage {
    users: Arc<RwLock<HashMap<Uuid, MemoryUser>>>,
    users_by_username: Arc<RwLock<HashMap<String, Uuid>>>,
    credentials: Arc<RwLock<HashMap<Uuid, MemoryCredential>>>,
    credentials_by_user: Arc<RwLock<HashMap<Uuid, Vec<Uuid>>>>,
    challenges: Arc<RwLock<HashMap<Vec<u8>, MemoryChallenge>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            users_by_username: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
            credentials_by_user: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn find_user_by_username(&self, username: &str) -> Option<MemoryUser> {
        let users_by_username = self.users_by_username.read().unwrap();
        let users = self.users.read().unwrap();
        
        if let Some(user_id) = users_by_username.get(username) {
            users.get(user_id).cloned()
        } else {
            None
        }
    }

    pub fn find_user_by_id(&self, user_id: Uuid) -> Option<MemoryUser> {
        let users = self.users.read().unwrap();
        users.get(&user_id).cloned()
    }

    pub fn create_user(&self, username: String, display_name: String, user_id: Vec<u8>) -> MemoryUser {
        let id = Uuid::new_v4();
        let user = MemoryUser {
            id,
            username: username.clone(),
            display_name,
            user_id,
            created_at: Utc::now(),
            active: true,
        };

        {
            let mut users = self.users.write().unwrap();
            users.insert(id, user.clone());
        }
        {
            let mut users_by_username = self.users_by_username.write().unwrap();
            users_by_username.insert(username, id);
        }

        user
    }

    pub fn get_user_credentials(&self, user_id: Uuid) -> Vec<MemoryCredential> {
        let credentials_by_user = self.credentials_by_user.read().unwrap();
        let credentials = self.credentials.read().unwrap();

        if let Some(credential_ids) = credentials_by_user.get(&user_id) {
            credential_ids
                .iter()
                .filter_map(|cred_id| credentials.get(cred_id))
                .filter(|cred| cred.active)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn store_credential(&self, user_id: Uuid, credential_id: Vec<u8>, public_key: Vec<u8>) -> MemoryCredential {
        let id = Uuid::new_v4();
        let credential = MemoryCredential {
            id,
            user_id,
            credential_id,
            public_key,
            counter: 0,
            created_at: Utc::now(),
            active: true,
        };

        {
            let mut credentials = self.credentials.write().unwrap();
            credentials.insert(id, credential.clone());
        }
        {
            let mut credentials_by_user = self.credentials_by_user.write().unwrap();
            credentials_by_user.entry(user_id).or_insert_with(Vec::new).push(id);
        }

        credential
    }

    pub fn store_challenge(&self, challenge: Vec<u8>, user_id: Option<Uuid>, challenge_type: String, expires_at: DateTime<Utc>) {
        let challenge_obj = MemoryChallenge {
            id: Uuid::new_v4(),
            challenge: challenge.clone(),
            user_id,
            challenge_type,
            created_at: Utc::now(),
            expires_at,
            consumed: false,
        };

        let mut challenges = self.challenges.write().unwrap();
        challenges.insert(challenge, challenge_obj);
    }

    pub fn find_and_consume_challenge(&self, challenge: &[u8], challenge_type: &str) -> Option<MemoryChallenge> {
        let mut challenges = self.challenges.write().unwrap();
        
        if let Some(stored_challenge) = challenges.get_mut(challenge) {
            if stored_challenge.challenge_type == challenge_type && 
               !stored_challenge.consumed && 
               stored_challenge.expires_at > Utc::now() {
                stored_challenge.consumed = true;
                return Some(stored_challenge.clone());
            }
        }
        None
    }

    pub fn update_credential_counter(&self, credential_id: &[u8], new_counter: i64) {
        let mut credentials = self.credentials.write().unwrap();
        
        for credential in credentials.values_mut() {
            if credential.credential_id == credential_id {
                credential.counter = new_counter;
                break;
            }
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}