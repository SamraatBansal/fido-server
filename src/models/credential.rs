//! Credential domain model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::proto::{COSEAlgorithmIdentifier, AuthenticatorTransport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String, // Base64url encoded
    pub public_key: Vec<u8>,
    pub sign_count: u64,
    pub attestation_type: String,
    pub aaguid: Option<Uuid>,
    pub transports: Vec<AuthenticatorTransport>,
    pub algorithm: COSEAlgorithmIdentifier,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

impl Credential {
    pub fn new(
        user_id: Uuid,
        credential_id: String,
        public_key: Vec<u8>,
        attestation_type: String,
        aaguid: Option<Uuid>,
        transports: Vec<AuthenticatorTransport>,
        algorithm: COSEAlgorithmIdentifier,
    ) -> Result<Self, crate::error::AppError> {
        // Validate credential ID length
        if credential_id.is_empty() || credential_id.len() > 1024 {
            return Err(crate::error::AppError::InvalidInput(
                "Credential ID must be between 1 and 1024 characters".to_string(),
            ));
        }

        // Validate public key length
        if public_key.len() < 32 || public_key.len() > 1024 {
            return Err(crate::error::AppError::InvalidInput(
                "Public key must be between 32 and 1024 bytes".to_string(),
            ));
        }

        let now = Utc::now();
        Ok(Credential {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            public_key,
            sign_count: 0,
            attestation_type,
            aaguid,
            transports,
            algorithm,
            created_at: now,
            last_used_at: None,
            is_active: true,
        })
    }

    pub fn update_sign_count(&mut self, new_count: u64) -> Result<(), crate::error::AppError> {
        // Prevent replay attacks - sign count should never decrease
        if new_count <= self.sign_count {
            return Err(crate::error::AppError::ReplayAttack(
                "Sign count did not increase - possible replay attack".to_string(),
            ));
        }

        self.sign_count = new_count;
        self.last_used_at = Some(Utc::now());
        Ok(())
    }

    pub fn credential_id_bytes(&self) -> Result<Vec<u8>, crate::error::AppError> {
        base64::decode_config(&self.credential_id, base64::URL_SAFE_NO_PAD)
            .map_err(|e| crate::error::AppError::InvalidInput(format!("Invalid credential ID encoding: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs::proto::COSEAlgorithmIdentifier::ES256;

    #[test]
    fn test_credential_creation_valid() {
        let user_id = Uuid::new_v4();
        let credential_id = base64::encode_config(b"test_credential_id", base64::URL_SAFE_NO_PAD);
        let public_key = vec![1u8; 32];
        let transports = vec![AuthenticatorTransport::Internal];

        let credential = Credential::new(
            user_id,
            credential_id.clone(),
            public_key.clone(),
            "packed".to_string(),
            None,
            transports,
            ES256,
        ).unwrap();

        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.sign_count, 0);
        assert_eq!(credential.attestation_type, "packed");
        assert!(credential.is_active);
    }

    #[test]
    fn test_credential_creation_empty_id() {
        let user_id = Uuid::new_v4();
        let public_key = vec![1u8; 32];
        let transports = vec![AuthenticatorTransport::Internal];

        let result = Credential::new(
            user_id,
            "".to_string(),
            public_key,
            "packed".to_string(),
            None,
            transports,
            ES256,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_credential_creation_long_id() {
        let user_id = Uuid::new_v4();
        let long_id = "a".repeat(1025);
        let public_key = vec![1u8; 32];
        let transports = vec![AuthenticatorTransport::Internal];

        let result = Credential::new(
            user_id,
            long_id,
            public_key,
            "packed".to_string(),
            None,
            transports,
            ES256,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_credential_creation_short_public_key() {
        let user_id = Uuid::new_v4();
        let credential_id = base64::encode_config(b"test_credential_id", base64::URL_SAFE_NO_PAD);
        let public_key = vec![1u8; 31]; // Too short
        let transports = vec![AuthenticatorTransport::Internal];

        let result = Credential::new(
            user_id,
            credential_id,
            public_key,
            "packed".to_string(),
            None,
            transports,
            ES256,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_update_sign_count_valid() {
        let user_id = Uuid::new_v4();
        let credential_id = base64::encode_config(b"test_credential_id", base64::URL_SAFE_NO_PAD);
        let public_key = vec![1u8; 32];
        let transports = vec![AuthenticatorTransport::Internal];

        let mut credential = Credential::new(
            user_id,
            credential_id,
            public_key,
            "packed".to_string(),
            None,
            transports,
            ES256,
        ).unwrap();

        assert!(credential.update_sign_count(5).is_ok());
        assert_eq!(credential.sign_count, 5);
        assert!(credential.last_used_at.is_some());
    }

    #[test]
    fn test_update_sign_count_replay_attack() {
        let user_id = Uuid::new_v4();
        let credential_id = base64::encode_config(b"test_credential_id", base64::URL_SAFE_NO_PAD);
        let public_key = vec![1u8; 32];
        let transports = vec![AuthenticatorTransport::Internal];

        let mut credential = Credential::new(
            user_id,
            credential_id,
            public_key,
            "packed".to_string(),
            None,
            transports,
            ES256,
        ).unwrap();

        // Set initial count
        credential.sign_count = 10;

        // Try to set same count (replay attack)
        let result = credential.update_sign_count(10);
        assert!(result.is_err());

        // Try to set lower count (replay attack)
        let result = credential.update_sign_count(5);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_id_bytes() {
        let user_id = Uuid::new_v4();
        let credential_id_bytes = b"test_credential_id";
        let credential_id = base64::encode_config(credential_id_bytes, base64::URL_SAFE_NO_PAD);
        let public_key = vec![1u8; 32];
        let transports = vec![AuthenticatorTransport::Internal];

        let credential = Credential::new(
            user_id,
            credential_id,
            public_key,
            "packed".to_string(),
            None,
            transports,
            ES256,
        ).unwrap();

        let decoded = credential.credential_id_bytes().unwrap();
        assert_eq!(decoded, credential_id_bytes);
    }
}