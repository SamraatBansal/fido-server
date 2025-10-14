//! Credential service for managing WebAuthn credentials

use crate::error::{AppError, Result};
use std::collections::HashMap;
use uuid::Uuid;

/// Credential entity
#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Uuid,
    pub credential_id: String,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: u64,
}

/// Credential service
pub struct CredentialService {
    credentials: std::sync::Arc<std::sync::Mutex<HashMap<String, Credential>>>,
}

impl CredentialService {
    /// Create a new credential service
    pub fn new() -> Self {
        Self {
            credentials: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Create a new credential
    pub fn create_credential(
        &self,
        credential_id: &str,
        user_id: Uuid,
        public_key: Vec<u8>,
    ) -> Result<Credential> {
        let mut credentials = self.credentials.lock().unwrap();
        
        // Check if credential already exists
        if credentials.contains_key(credential_id) {
            return Err(AppError::conflict("Credential already exists"));
        }

        let credential = Credential {
            id: Uuid::new_v4(),
            credential_id: credential_id.to_string(),
            user_id,
            public_key,
            sign_count: 0,
        };

        credentials.insert(credential_id.to_string(), credential.clone());
        Ok(credential)
    }

    /// Get credential by ID
    pub fn get_credential(&self, credential_id: &str) -> Result<Credential> {
        let credentials = self.credentials.lock().unwrap();
        
        credentials
            .get(credential_id)
            .cloned()
            .ok_or_else(|| AppError::not_found("Credential not found"))
    }

    /// Get credentials by user ID
    pub fn get_credentials_by_user(&self, user_id: Uuid) -> Vec<Credential> {
        let credentials = self.credentials.lock().unwrap();
        
        credentials
            .values()
            .filter(|cred| cred.user_id == user_id)
            .cloned()
            .collect()
    }

    /// Update sign count
    pub fn update_sign_count(&self, credential_id: &str, new_count: u64) -> Result<()> {
        let mut credentials = self.credentials.lock().unwrap();
        
        if let Some(credential) = credentials.get_mut(credential_id) {
            credential.sign_count = new_count;
            Ok(())
        } else {
            Err(AppError::not_found("Credential not found"))
        }
    }

    /// Delete credential
    pub fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let mut credentials = self.credentials.lock().unwrap();
        
        credentials
            .remove(credential_id)
            .ok_or_else(|| AppError::not_found("Credential not found"))?;
        
        Ok(())
    }
}

impl Default for CredentialService {
    fn default() -> Self {
        Self::new()
    }
}