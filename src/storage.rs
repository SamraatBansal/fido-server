//! Storage layer for FIDO2/WebAuthn server

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use chrono::{DateTime, Utc};

use crate::error::WebAuthnError;

/// User information stored in the system
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

/// Credential information with metadata
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Challenge state for registration/authentication flows
#[derive(Debug, Clone)]
pub struct ChallengeInfo {
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub state: ChallengeState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ChallengeState {
    Registration(PasskeyRegistration),
    Authentication(PasskeyAuthentication),
}

/// Storage trait for abstracting data persistence
#[async_trait]
pub trait Storage: Send + Sync {
    // User operations
    async fn create_user(&self, username: &str, display_name: &str) -> Result<UserInfo, WebAuthnError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<UserInfo>, WebAuthnError>;
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<UserInfo>, WebAuthnError>;

    // Credential operations  
    async fn store_credential(&self, user_id: Uuid, passkey: Passkey) -> Result<(), WebAuthnError>;
    async fn get_credentials_for_user(&self, user_id: Uuid) -> Result<Vec<CredentialInfo>, WebAuthnError>;
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<CredentialInfo>, WebAuthnError>;
    async fn update_credential_counter(&self, credential_id: &[u8], counter: u32) -> Result<(), WebAuthnError>;

    // Challenge operations
    async fn store_registration_challenge(&self, user_id: Uuid, challenge: &str, state: PasskeyRegistration) -> Result<(), WebAuthnError>;
    async fn store_authentication_challenge(&self, username: &str, challenge: &str, state: PasskeyAuthentication) -> Result<(), WebAuthnError>;
    async fn get_registration_challenge(&self, user_id: Uuid) -> Result<Option<(String, PasskeyRegistration)>, WebAuthnError>;
    async fn get_authentication_challenge(&self, username: &str) -> Result<Option<(String, PasskeyAuthentication)>, WebAuthnError>;
    async fn remove_challenge(&self, challenge: &str) -> Result<(), WebAuthnError>;
    
    // Cleanup operations
    async fn cleanup_expired_challenges(&self) -> Result<(), WebAuthnError>;
}

/// In-memory storage implementation for testing/demo
pub struct InMemoryStorage {
    users_by_username: RwLock<HashMap<String, UserInfo>>,
    users_by_id: RwLock<HashMap<Uuid, UserInfo>>,
    credentials: RwLock<HashMap<Vec<u8>, CredentialInfo>>,
    credentials_by_user: RwLock<HashMap<Uuid, Vec<Vec<u8>>>>,
    challenges: RwLock<HashMap<String, ChallengeInfo>>,
    registration_challenges: RwLock<HashMap<Uuid, (String, PasskeyRegistration)>>,
    authentication_challenges: RwLock<HashMap<String, (String, PasskeyAuthentication)>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            users_by_username: RwLock::new(HashMap::new()),
            users_by_id: RwLock::new(HashMap::new()),
            credentials: RwLock::new(HashMap::new()),
            credentials_by_user: RwLock::new(HashMap::new()),
            challenges: RwLock::new(HashMap::new()),
            registration_challenges: RwLock::new(HashMap::new()),
            authentication_challenges: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn create_user(&self, username: &str, display_name: &str) -> Result<UserInfo, WebAuthnError> {
        let user = UserInfo {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
        };

        {
            let mut users_by_username = self.users_by_username.write().unwrap();
            let mut users_by_id = self.users_by_id.write().unwrap();
            
            users_by_username.insert(username.to_string(), user.clone());
            users_by_id.insert(user.id, user.clone());
        }

        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<UserInfo>, WebAuthnError> {
        let users = self.users_by_username.read().unwrap();
        Ok(users.get(username).cloned())
    }

    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<UserInfo>, WebAuthnError> {
        let users = self.users_by_id.read().unwrap();
        Ok(users.get(&user_id).cloned())
    }

    async fn store_credential(&self, user_id: Uuid, passkey: Passkey) -> Result<(), WebAuthnError> {
        let credential_id = passkey.cred_id().to_vec();
        
        let credential_info = CredentialInfo {
            credential_id: credential_id.clone(),
            user_id,
            passkey,
            created_at: Utc::now(),
            last_used: None,
        };

        {
            let mut credentials = self.credentials.write().unwrap();
            let mut credentials_by_user = self.credentials_by_user.write().unwrap();
            
            credentials.insert(credential_id.clone(), credential_info);
            credentials_by_user.entry(user_id).or_default().push(credential_id);
        }

        Ok(())
    }

    async fn get_credentials_for_user(&self, user_id: Uuid) -> Result<Vec<CredentialInfo>, WebAuthnError> {
        let credentials = self.credentials.read().unwrap();
        let credentials_by_user = self.credentials_by_user.read().unwrap();
        
        let empty_vec = vec![];
        let credential_ids = credentials_by_user.get(&user_id).unwrap_or(&empty_vec);
        let mut user_credentials = Vec::new();
        
        for credential_id in credential_ids {
            if let Some(credential_info) = credentials.get(credential_id) {
                user_credentials.push(credential_info.clone());
            }
        }
        
        Ok(user_credentials)
    }

    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<CredentialInfo>, WebAuthnError> {
        let credentials = self.credentials.read().unwrap();
        Ok(credentials.get(credential_id).cloned())
    }

    async fn update_credential_counter(&self, credential_id: &[u8], _counter: u32) -> Result<(), WebAuthnError> {
        let mut credentials = self.credentials.write().unwrap();
        if let Some(credential_info) = credentials.get_mut(credential_id) {
            // Note: webauthn-rs handles counter internally, this is just for demonstration
            credential_info.last_used = Some(Utc::now());
        }
        Ok(())
    }

    async fn store_registration_challenge(&self, user_id: Uuid, challenge: &str, state: PasskeyRegistration) -> Result<(), WebAuthnError> {
        let mut challenges = self.registration_challenges.write().unwrap();
        challenges.insert(user_id, (challenge.to_string(), state));
        Ok(())
    }

    async fn store_authentication_challenge(&self, username: &str, challenge: &str, state: PasskeyAuthentication) -> Result<(), WebAuthnError> {
        let mut challenges = self.authentication_challenges.write().unwrap();
        challenges.insert(username.to_string(), (challenge.to_string(), state));
        Ok(())
    }

    async fn get_registration_challenge(&self, user_id: Uuid) -> Result<Option<(String, PasskeyRegistration)>, WebAuthnError> {
        let challenges = self.registration_challenges.read().unwrap();
        Ok(challenges.get(&user_id).cloned())
    }

    async fn get_authentication_challenge(&self, username: &str) -> Result<Option<(String, PasskeyAuthentication)>, WebAuthnError> {
        let challenges = self.authentication_challenges.read().unwrap();
        Ok(challenges.get(username).cloned())
    }

    async fn remove_challenge(&self, challenge: &str) -> Result<(), WebAuthnError> {
        // Remove from both registration and authentication challenge stores
        {
            let mut reg_challenges = self.registration_challenges.write().unwrap();
            reg_challenges.retain(|_, (stored_challenge, _)| stored_challenge != challenge);
        }
        
        {
            let mut auth_challenges = self.authentication_challenges.write().unwrap();
            auth_challenges.retain(|_, (stored_challenge, _)| stored_challenge != challenge);
        }
        
        Ok(())
    }

    async fn cleanup_expired_challenges(&self) -> Result<(), WebAuthnError> {
        // For in-memory implementation, we'll rely on the natural expiry handling
        // In production, this would clean up expired challenges from persistent storage
        Ok(())
    }
}