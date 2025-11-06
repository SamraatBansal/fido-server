use crate::api::*;
use crate::error::{AppError, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge_type: String,
    pub challenge_data: Vec<u8>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Default)]
pub struct MemoryStorage {
    users: Arc<Mutex<HashMap<Uuid, MemoryUser>>>,
    users_by_username: Arc<Mutex<HashMap<String, Uuid>>>,
    credentials: Arc<Mutex<HashMap<Uuid, MemoryCredential>>>,
    credentials_by_user: Arc<Mutex<HashMap<Uuid, Vec<Uuid>>>>,
    challenges: Arc<Mutex<HashMap<Uuid, MemoryChallenge>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_user(&self, username: &str, display_name: &str) -> Result<Uuid> {
        let user_id = Uuid::new_v4();
        let user = MemoryUser {
            id: user_id,
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        let mut users = self.users.lock().unwrap();
        let mut users_by_username = self.users_by_username.lock().unwrap();

        users.insert(user_id, user);
        users_by_username.insert(username.to_string(), user_id);

        Ok(user_id)
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<MemoryUser>> {
        let users_by_username = self.users_by_username.lock().unwrap();
        let users = self.users.lock().unwrap();

        if let Some(&user_id) = users_by_username.get(username) {
            Ok(users.get(&user_id).cloned())
        } else {
            Ok(None)
        }
    }

    pub fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<MemoryUser>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(&user_id).cloned())
    }

    pub fn store_credential(&self, user_id: Uuid, credential_id: &[u8], public_key: &[u8]) -> Result<()> {
        let cred_id = Uuid::new_v4();
        let credential = MemoryCredential {
            id: cred_id,
            user_id,
            credential_id: credential_id.to_vec(),
            public_key: public_key.to_vec(),
            sign_count: 0,
        };

        let mut credentials = self.credentials.lock().unwrap();
        let mut credentials_by_user = self.credentials_by_user.lock().unwrap();

        credentials.insert(cred_id, credential);
        credentials_by_user
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(cred_id);

        Ok(())
    }

    pub fn get_credentials_for_user(&self, user_id: Uuid) -> Result<Vec<MemoryCredential>> {
        let credentials = self.credentials.lock().unwrap();
        let credentials_by_user = self.credentials_by_user.lock().unwrap();

        if let Some(credential_ids) = credentials_by_user.get(&user_id) {
            let mut result = Vec::new();
            for &cred_id in credential_ids {
                if let Some(credential) = credentials.get(&cred_id) {
                    result.push(credential.clone());
                }
            }
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn store_challenge(&self, user_id: Uuid, challenge_type: &str, challenge_data: &[u8]) -> Result<Uuid> {
        let challenge_id = Uuid::new_v4();
        let challenge = MemoryChallenge {
            id: challenge_id,
            user_id,
            challenge_type: challenge_type.to_string(),
            challenge_data: challenge_data.to_vec(),
            expires_at: Utc::now() + Duration::seconds(300), // 5 minutes
        };

        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert(challenge_id, challenge);

        Ok(challenge_id)
    }

    pub fn get_challenge(&self, challenge_type: &str) -> Result<Option<MemoryChallenge>> {
        let challenges = self.challenges.lock().unwrap();
        let now = Utc::now();

        // Find the most recent valid challenge of the given type
        let mut valid_challenge = None;
        let mut latest_time = None;

        for challenge in challenges.values() {
            if challenge.challenge_type == challenge_type && challenge.expires_at > now {
                if latest_time.is_none() || challenge.expires_at > latest_time.unwrap() {
                    latest_time = Some(challenge.expires_at);
                    valid_challenge = Some(challenge.clone());
                }
            }
        }

        Ok(valid_challenge)
    }

    pub fn remove_challenge(&self, challenge_id: Uuid) -> Result<()> {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.remove(&challenge_id);
        Ok(())
    }

    pub fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut challenges = self.challenges.lock().unwrap();
        let now = Utc::now();
        
        challenges.retain(|_, challenge| challenge.expires_at > now);
        
        Ok(())
    }
}