use crate::{error::Result, types::*};
use chrono::{DateTime, Utc, Duration};
use std::{collections::HashMap, sync::RwLock};
use uuid::Uuid;

#[derive(Clone)]
pub struct MemoryDatabase {
    users: std::sync::Arc<RwLock<HashMap<String, User>>>,
    credentials: std::sync::Arc<RwLock<HashMap<Vec<u8>, Credential>>>,
    reg_challenges: std::sync::Arc<RwLock<HashMap<Vec<u8>, RegistrationChallenge>>>,
    auth_challenges: std::sync::Arc<RwLock<HashMap<Vec<u8>, AuthenticationChallenge>>>,
}

impl MemoryDatabase {
    pub fn new() -> Self {
        Self {
            users: std::sync::Arc::new(RwLock::new(HashMap::new())),
            credentials: std::sync::Arc::new(RwLock::new(HashMap::new())),
            reg_challenges: std::sync::Arc::new(RwLock::new(HashMap::new())),
            auth_challenges: std::sync::Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_user(&self, user: NewUser) -> Result<User> {
        let mut users = self.users.write().unwrap();
        
        let new_user = User {
            id: Uuid::new_v4(),
            username: user.username.clone(),
            display_name: user.display_name,
            user_handle: user.user_handle,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        users.insert(user.username, new_user.clone());
        Ok(new_user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let users = self.users.read().unwrap();
        Ok(users.get(username).cloned())
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let users = self.users.read().unwrap();
        Ok(users.values().find(|u| u.id == user_id).cloned())
    }

    pub async fn get_user_by_handle(&self, user_handle: &[u8]) -> Result<Option<User>> {
        let users = self.users.read().unwrap();
        Ok(users.values().find(|u| u.user_handle == user_handle).cloned())
    }

    pub async fn create_credential(&self, credential: NewCredential) -> Result<Credential> {
        let mut credentials = self.credentials.write().unwrap();
        
        let new_credential = Credential {
            id: Uuid::new_v4(),
            user_id: credential.user_id,
            credential_id: credential.credential_id.clone(),
            public_key: credential.public_key,
            sign_count: credential.sign_count,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            attestation_format: credential.attestation_format,
            created_at: Utc::now(),
            last_used_at: None,
            updated_at: Utc::now(),
        };

        credentials.insert(credential.credential_id, new_credential.clone());
        Ok(new_credential)
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let credentials = self.credentials.read().unwrap();
        Ok(credentials.get(credential_id).cloned())
    }

    pub async fn get_credentials_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let credentials = self.credentials.read().unwrap();
        Ok(credentials.values()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect())
    }

    pub async fn update_credential_sign_count(
        &self,
        credential_id: &[u8],
        sign_count: i64,
    ) -> Result<()> {
        let mut credentials = self.credentials.write().unwrap();
        if let Some(credential) = credentials.get_mut(credential_id) {
            credential.sign_count = sign_count;
            credential.last_used_at = Some(Utc::now());
            credential.updated_at = Utc::now();
        }
        Ok(())
    }

    pub async fn store_registration_challenge(
        &self,
        challenge: NewRegistrationChallenge,
    ) -> Result<RegistrationChallenge> {
        let mut reg_challenges = self.reg_challenges.write().unwrap();
        
        let new_challenge = RegistrationChallenge {
            id: Uuid::new_v4(),
            user_id: challenge.user_id,
            challenge: challenge.challenge.clone(),
            state_data: challenge.state_data,
            expires_at: challenge.expires_at,
            created_at: Utc::now(),
        };

        reg_challenges.insert(challenge.challenge, new_challenge.clone());
        Ok(new_challenge)
    }

    pub async fn get_registration_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Option<RegistrationChallenge>> {
        let reg_challenges = self.reg_challenges.read().unwrap();
        if let Some(reg_challenge) = reg_challenges.get(challenge) {
            if reg_challenge.expires_at > Utc::now() {
                return Ok(Some(reg_challenge.clone()));
            }
        }
        Ok(None)
    }

    pub async fn delete_registration_challenge(&self, challenge: &[u8]) -> Result<()> {
        let mut reg_challenges = self.reg_challenges.write().unwrap();
        reg_challenges.remove(challenge);
        Ok(())
    }

    pub async fn store_authentication_challenge(
        &self,
        challenge: NewAuthenticationChallenge,
    ) -> Result<AuthenticationChallenge> {
        let mut auth_challenges = self.auth_challenges.write().unwrap();
        
        let new_challenge = AuthenticationChallenge {
            id: Uuid::new_v4(),
            user_id: challenge.user_id,
            challenge: challenge.challenge.clone(),
            state_data: challenge.state_data,
            expires_at: challenge.expires_at,
            created_at: Utc::now(),
        };

        auth_challenges.insert(challenge.challenge, new_challenge.clone());
        Ok(new_challenge)
    }

    pub async fn get_authentication_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Option<AuthenticationChallenge>> {
        let auth_challenges = self.auth_challenges.read().unwrap();
        if let Some(auth_challenge) = auth_challenges.get(challenge) {
            if auth_challenge.expires_at > Utc::now() {
                return Ok(Some(auth_challenge.clone()));
            }
        }
        Ok(None)
    }

    pub async fn delete_authentication_challenge(&self, challenge: &[u8]) -> Result<()> {
        let mut auth_challenges = self.auth_challenges.write().unwrap();
        auth_challenges.remove(challenge);
        Ok(())
    }

    pub async fn cleanup_expired_challenges(&self) -> Result<()> {
        let now = Utc::now();
        
        {
            let mut reg_challenges = self.reg_challenges.write().unwrap();
            reg_challenges.retain(|_, challenge| challenge.expires_at > now);
        }
        
        {
            let mut auth_challenges = self.auth_challenges.write().unwrap();
            auth_challenges.retain(|_, challenge| challenge.expires_at > now);
        }
        
        Ok(())
    }
}