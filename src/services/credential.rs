use crate::db::models::{ActiveCredential, NewCredential};
use crate::db::repositories::CredentialRepository;
use crate::error::{AppError, Result};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct CredentialService {
    repository: Arc<CredentialRepository>,
}

impl CredentialService {
    pub fn new(repository: CredentialRepository) -> Self {
        Self {
            repository: Arc::new(repository),
        }
    }

    pub async fn create_credential(&self, user_id: Uuid, passkey: Passkey) -> Result<uuid::Uuid> {
        let new_credential = NewCredential {
            user_id,
            credential_id: passkey.cred_id().to_vec(),
            public_key: passkey.cred().cose_key.to_vec(),
            sign_count: passkey.counter() as i64,
            backup_eligible: passkey.backup_eligible(),
            backup_state: passkey.backup_state(),
            attestation_type: passkey.attestation_type().map(|t| format!("{:?}", t)),
            transports: Some(
                passkey
                    .transports()
                    .iter()
                    .map(|t| format!("{:?}", t))
                    .collect(),
            ),
            aaguid: passkey.aaguid().map(|uuid| uuid.as_bytes().to_vec()),
        };

        let credential = self.repository.create_credential(new_credential).await?;
        Ok(credential.id)
    }

    pub async fn get_credentials_for_user(&self, username: &str) -> Result<Vec<ActiveCredential>> {
        self.repository.get_credentials_for_user(username).await
    }

    pub async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<webauthn_rs::prelude::CredentialID>> {
        let credentials = self.repository.get_user_credentials(user_id).await?;
        
        Ok(credentials
            .into_iter()
            .map(|cred| cred.credential_id)
            .collect())
    }

    pub async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<ActiveCredential>> {
        self.repository
            .get_active_credential_by_id(credential_id)
            .await
    }

    pub async fn update_sign_count(&self, credential_id: &[u8], new_count: u32) -> Result<()> {
        self.repository
            .update_sign_count(credential_id, new_count)
            .await
    }

    pub async fn deactivate_credential(&self, credential_uuid: Uuid) -> Result<()> {
        self.repository.deactivate_credential(credential_uuid).await
    }

    pub async fn count_user_credentials(&self, user_id: Uuid) -> Result<i64> {
        self.repository.count_user_credentials(user_id).await
    }

    pub fn convert_to_passkey(&self, credential: &ActiveCredential) -> Result<Passkey> {
        // For now, return an error - this will need proper implementation 
        // based on the stored credential data format
        Err(AppError::validation("Passkey conversion not implemented - will be fixed in next iteration"))
    }

    pub fn create_credential_descriptors(
        &self,
        credentials: &[ActiveCredential],
    ) -> Vec<crate::schema::ServerPublicKeyCredentialDescriptor> {
        credentials
            .iter()
            .map(|cred| crate::schema::ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: base64::encode_config(&cred.credential_id, base64::URL_SAFE_NO_PAD),
                transports: cred.transports.clone(),
            })
            .collect()
    }

    pub fn convert_to_credential_ids(&self, credentials: &[ActiveCredential]) -> Vec<CredentialID> {
        credentials
            .iter()
            .map(|cred| cred.credential_id.clone())
            .collect()
    }
}