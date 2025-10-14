use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
}

impl Credential {
    pub fn new(
        user_id: Uuid,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        counter: u32,
        backup_eligible: bool,
        backup_state: bool,
        attestation_format: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            public_key,
            counter,
            backup_eligible,
            backup_state,
            attestation_format,
            created_at: now,
            last_used: now,
        }
    }

    pub fn update_counter(&mut self, new_counter: u32) -> crate::Result<()> {
        if new_counter <= self.counter {
            return Err(crate::error::FidoError::CounterRollback {
                stored: self.counter,
                received: new_counter,
            });
        }
        self.counter = new_counter;
        self.last_used = Utc::now();
        Ok(())
    }

    pub fn credential_id_base64(&self) -> String {
        base64::encode_config(&self.credential_id, base64::URL_SAFE_NO_PAD)
    }
}

#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub credential_id: String, // Base64URL encoded
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub counter: u32,
}

impl From<Credential> for CredentialResponse {
    fn from(credential: Credential) -> Self {
        Self {
            id: credential.id,
            credential_id: credential.credential_id_base64(),
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            attestation_format: credential.attestation_format,
            created_at: credential.created_at,
            last_used: credential.last_used,
            counter: credential.counter,
        }
    }
}

// Helper to convert from webauthn-rs types
impl TryFrom<&PasskeyRegistration> for Credential {
    type Error = crate::error::FidoError;

    fn try_from(passkey: &PasskeyRegistration) -> Result<Self, Self::Error> {
        // Extract credential data from PasskeyRegistration
        // Note: This is a simplified conversion - in practice you'd need to
        // properly extract all the necessary data from the PasskeyRegistration
        
        let credential_id = passkey.cred_id().to_vec();
        let public_key = Vec::new(); // Would extract from passkey.cred().cose_key
        
        Ok(Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(), // Would be set by caller
            credential_id,
            public_key,
            counter: passkey.counter(),
            backup_eligible: passkey.backup_eligible(),
            backup_state: passkey.backup_state(),
            attestation_format: None, // Would extract from attestation
            created_at: Utc::now(),
            last_used: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        let user_id = Uuid::new_v4();
        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];
        
        let credential = Credential::new(
            user_id,
            credential_id.clone(),
            public_key.clone(),
            0,
            false,
            false,
            Some("packed".to_string()),
        );
        
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.counter, 0);
        assert_eq!(credential.attestation_format, Some("packed".to_string()));
    }

    #[test]
    fn test_counter_update() {
        let mut credential = Credential::new(
            Uuid::new_v4(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            5,
            false,
            false,
            None,
        );
        
        // Valid counter update
        assert!(credential.update_counter(6).is_ok());
        assert_eq!(credential.counter, 6);
        
        // Invalid counter update (rollback)
        assert!(credential.update_counter(5).is_err());
        assert!(credential.update_counter(6).is_err());
    }

    #[test]
    fn test_credential_id_base64() {
        let credential = Credential::new(
            Uuid::new_v4(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            0,
            false,
            false,
            None,
        );
        
        let base64_id = credential.credential_id_base64();
        assert!(!base64_id.is_empty());
        
        // Verify it's valid base64
        let decoded = base64::decode_config(&base64_id, base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(decoded, vec![1, 2, 3, 4]);
    }
}