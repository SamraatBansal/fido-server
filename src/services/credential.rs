use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::error::{AppError, AppResult};
use crate::models::StoredCredential;
use crate::storage::Storage;

pub struct CredentialService {
    storage: Arc<dyn Storage>,
}

impl CredentialService {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    pub async fn create_credential(&self, user_id: Uuid, passkey: Passkey) -> AppResult<StoredCredential> {
        let credential = StoredCredential {
            id: Uuid::new_v4(),
            user_id,
            credential_id: passkey.cred_id().to_vec(),
            passkey,
            created_at: Utc::now(),
            last_used_at: None,
        };

        self.storage.create_credential(credential).await
    }

    pub async fn get_user_credentials(&self, user_id: Uuid) -> AppResult<Vec<StoredCredential>> {
        self.storage.get_credentials_by_user_id(user_id).await
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> AppResult<Option<StoredCredential>> {
        self.storage.get_credential_by_id(credential_id).await
    }

    pub async fn update_credential_last_used(&self, credential_id: &[u8]) -> AppResult<()> {
        self.storage.update_credential_last_used(credential_id, Utc::now()).await
    }

    pub async fn get_user_passkeys(&self, user_id: Uuid) -> AppResult<Vec<Passkey>> {
        let credentials = self.get_user_credentials(user_id).await?;
        Ok(credentials.into_iter().map(|c| c.passkey).collect())
    }

    pub async fn get_exclude_list(&self, user_id: Uuid) -> AppResult<Vec<CredentialID>> {
        let credentials = self.get_user_credentials(user_id).await?;
        Ok(credentials.into_iter().map(|c| c.passkey.cred_id().clone()).collect())
    }
}