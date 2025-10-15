use crate::models::{User, Credential, Challenge, ChallengeType};
use crate::error::{AppError, AppResult};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};

// In-memory storage for testing and development
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    users: Arc<Mutex<HashMap<String, User>>>,
    credentials: Arc<Mutex<HashMap<String, Vec<Credential>>>>,
    challenges: Arc<Mutex<HashMap<Vec<u8>, Challenge>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_user(&self, username: &str, display_name: &str) -> AppResult<User> {
        let mut users = self.users.lock().unwrap();
        
        if users.contains_key(username) {
            return Err(AppError::InvalidRequest("User already exists".to_string()));
        }

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
        };

        users.insert(username.to_string(), user.clone());
        Ok(user)
    }

    pub fn get_user(&self, username: &str) -> AppResult<Option<User>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(username).cloned())
    }

    pub fn store_credential(&self, user_id: &str, credential: Credential) -> AppResult<()> {
        let mut credentials = self.credentials.lock().unwrap();
        credentials.entry(user_id.to_string()).or_insert_with(Vec::new).push(credential);
        Ok(())
    }

    pub fn get_credentials(&self, user_id: &str) -> AppResult<Vec<Credential>> {
        let credentials = self.credentials.lock().unwrap();
        Ok(credentials.get(user_id).cloned().unwrap_or_default())
    }

    pub fn get_credential_by_id(&self, credential_id: &[u8]) -> AppResult<Option<Credential>> {
        let credentials = self.credentials.lock().unwrap();
        for user_credentials in credentials.values() {
            for credential in user_credentials {
                if credential.id == credential_id {
                    return Ok(Some(credential.clone()));
                }
            }
        }
        Ok(None)
    }

    pub fn update_credential_sign_count(&self, credential_id: &[u8], sign_count: u32) -> AppResult<()> {
        let mut credentials = self.credentials.lock().unwrap();
        for user_credentials in credentials.values_mut() {
            for credential in user_credentials.iter_mut() {
                if credential.id == credential_id {
                    credential.sign_count = sign_count;
                    return Ok(());
                }
            }
        }
        Err(AppError::CredentialNotFound)
    }

    pub fn store_challenge(&self, challenge: Challenge) -> AppResult<()> {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert(challenge.challenge.clone(), challenge);
        Ok(())
    }

    pub fn get_challenge(&self, challenge_bytes: &[u8]) -> AppResult<Option<Challenge>> {
        let challenges = self.challenges.lock().unwrap();
        Ok(challenges.get(challenge_bytes).cloned())
    }

    pub fn mark_challenge_used(&self, challenge_bytes: &[u8]) -> AppResult<()> {
        let mut challenges = self.challenges.lock().unwrap();
        if let Some(challenge) = challenges.get_mut(challenge_bytes) {
            challenge.used = true;
            Ok(())
        } else {
            Err(AppError::ChallengeNotFound)
        }
    }

    pub fn cleanup_expired_challenges(&self) -> AppResult<usize> {
        let mut challenges = self.challenges.lock().unwrap();
        let now = Utc::now();
        let initial_count = challenges.len();
        
        challenges.retain(|_, challenge| challenge.expires_at > now);
        
        Ok(initial_count - challenges.len())
    }
}

// Challenge utilities
pub fn generate_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

pub fn create_challenge(user_id: &str, challenge_type: ChallengeType) -> Challenge {
    Challenge {
        challenge: generate_challenge(),
        user_id: user_id.to_string(),
        challenge_type,
        expires_at: Utc::now() + Duration::minutes(5), // 5 minute expiry
        used: false,
    }
}