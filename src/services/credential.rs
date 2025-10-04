//! Credential management service

use crate::db::models::Credential;
use uuid::Uuid;
use chrono::Utc;

/// Credential service
pub struct CredentialService {
    // In-memory storage (in production, use database)
    credentials: std::collections::HashMap<Uuid, Credential>,
    credential_id_index: std::collections::HashMap<Vec<u8>, Uuid>,
    user_credentials: std::collections::HashMap<Uuid, Vec<Uuid>>,
}

impl CredentialService {
    /// Create new credential service
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
            credential_id_index: std::collections::HashMap::new(),
            user_credentials: std::collections::HashMap::new(),
        }
    }

    /// Store credential
    pub fn store_credential(
        &mut self,
        user_id: Uuid,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        sign_count: i32,
        aaguid: Option<Vec<u8>>,
    ) -> crate::error::Result<Credential> {
        let credential_uuid = Uuid::new_v4();
        let now = Utc::now();
        
        let credential = Credential {
            id: credential_uuid,
            user_id,
            credential_id: credential_id.clone(),
            public_key,
            sign_count,
            aaguid,
            created_at: now,
            updated_at: now,
        };

        // Store in all indexes
        self.credentials.insert(credential_uuid, credential.clone());
        self.credential_id_index.insert(credential_id, credential_uuid);
        
        self.user_credentials
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(credential_uuid);
        
        Ok(credential)
    }

    /// Get user credentials
    pub fn get_user_credentials(&self, user_id: Uuid) -> crate::error::Result<Vec<Credential>> {
        if let Some(credential_ids) = self.user_credentials.get(&user_id) {
            let mut credentials = Vec::new();
            for cred_id in credential_ids {
                if let Some(credential) = self.credentials.get(cred_id) {
                    credentials.push(credential.clone());
                }
            }
            Ok(credentials)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get credential by ID
    pub fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        if let Some(cred_uuid) = self.credential_id_index.get(credential_id) {
            if let Some(credential) = self.credentials.get(cred_uuid) {
                return Ok(Some(credential.clone()));
            }
        }
        Ok(None)
    }

    /// Update credential usage
    pub fn update_credential_usage(
        &mut self,
        credential_id: &[u8],
        new_sign_count: i32,
    ) -> Result<()> {
        if let Some(cred_uuid) = self.credential_id_index.get(credential_id) {
            if let Some(credential) = self.credentials.get_mut(cred_uuid) {
                credential.sign_count = new_sign_count;
                credential.updated_at = Utc::now();
                return Ok(());
            }
        }
        Err(AppError::NotFound("Credential not found".to_string()))
    }

    /// Delete credential
    pub fn delete_credential(&mut self, credential_id: &[u8]) -> Result<()> {
        if let Some(cred_uuid) = self.credential_id_index.remove(credential_id) {
            if let Some(credential) = self.credentials.remove(&cred_uuid) {
                // Remove from user credentials
                if let Some(user_creds) = self.user_credentials.get_mut(&credential.user_id) {
                    user_creds.retain(|id| *id != cred_uuid);
                }
                return Ok(());
            }
        }
        Err(AppError::NotFound("Credential not found".to_string()))
    }
}