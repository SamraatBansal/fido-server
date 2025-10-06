//! Credential schema definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    /// Credential ID
    pub id: Vec<u8>,
    /// User ID this credential belongs to
    pub user_id: Uuid,
    /// COSE-encoded public key
    pub public_key: Vec<u8>,
    /// Signature counter
    pub sign_count: u64,
    /// Authenticator AAGUID
    pub aaguid: Option<Vec<u8>>,
    /// Attestation format
    pub attestation_format: String,
    /// Supported transports
    pub transports: Vec<String>,
    /// When the credential was created
    pub created_at: DateTime<Utc>,
    /// When the credential was last used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether the credential is eligible for backup
    pub backup_eligible: bool,
    /// Current backup state
    pub backup_state: bool,
}

impl Credential {
    /// Create a new credential
    pub fn new(
        id: Vec<u8>,
        user_id: Uuid,
        public_key: Vec<u8>,
        attestation_format: String,
        transports: Vec<String>,
    ) -> Self {
        Self {
            id,
            user_id,
            public_key,
            sign_count: 0,
            aaguid: None,
            attestation_format,
            transports,
            created_at: Utc::now(),
            last_used_at: None,
            backup_eligible: false,
            backup_state: false,
        }
    }

    /// Validate credential data
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Credential ID cannot be empty".to_string());
        }

        if self.id.len() > 1024 {
            return Err("Credential ID too long (max 1024 bytes)".to_string());
        }

        if self.public_key.is_empty() {
            return Err("Public key cannot be empty".to_string());
        }

        if self.attestation_format.is_empty() {
            return Err("Attestation format cannot be empty".to_string());
        }

        // Validate attestation format
        let valid_formats = ["packed", "fido-u2f", "none", "tpm", "android-key", "android-safetynet"];
        if !valid_formats.contains(&self.attestation_format.as_str()) {
            return Err(format!("Invalid attestation format: {}", self.attestation_format));
        }

        // Validate transports
        let valid_transports = ["usb", "nfc", "ble", "internal", "hybrid"];
        for transport in &self.transports {
            if !valid_transports.contains(&transport.as_str()) {
                return Err(format!("Invalid transport: {}", transport));
            }
        }

        Ok(())
    }

    /// Update the signature counter and last used timestamp
    pub fn update_usage(&mut self, new_sign_count: u64) {
        self.sign_count = new_sign_count;
        self.last_used_at = Some(Utc::now());
    }

    /// Check if the signature counter has regressed (potential cloning)
    pub fn has_counter_regression(&self, new_sign_count: u64) -> bool {
        new_sign_count < self.sign_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string(), "nfc".to_string()],
        );

        assert_eq!(credential.id, vec![1, 2, 3, 4]);
        assert_eq!(credential.sign_count, 0);
        assert_eq!(credential.attestation_format, "packed");
        assert!(credential.last_used_at.is_none());
    }

    #[test]
    fn test_credential_validation_success() {
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        assert!(credential.validate().is_ok());
    }

    #[test]
    fn test_credential_validation_empty_id() {
        let credential = Credential::new(
            vec![],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        assert!(credential.validate().is_err());
    }

    #[test]
    fn test_credential_validation_id_too_long() {
        let credential = Credential::new(
            vec![0; 1025],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        assert!(credential.validate().is_err());
    }

    #[test]
    fn test_credential_validation_empty_public_key() {
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        assert!(credential.validate().is_err());
    }

    #[test]
    fn test_credential_validation_invalid_attestation_format() {
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "invalid".to_string(),
            vec!["usb".to_string()],
        );

        assert!(credential.validate().is_err());
    }

    #[test]
    fn test_credential_validation_invalid_transport() {
        let credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["invalid".to_string()],
        );

        assert!(credential.validate().is_err());
    }

    #[test]
    fn test_update_usage() {
        let mut credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        credential.update_usage(42);
        assert_eq!(credential.sign_count, 42);
        assert!(credential.last_used_at.is_some());
    }

    #[test]
    fn test_counter_regression_detection() {
        let mut credential = Credential::new(
            vec![1, 2, 3, 4],
            Uuid::new_v4(),
            vec![5, 6, 7, 8],
            "packed".to_string(),
            vec!["usb".to_string()],
        );

        credential.update_usage(10);

        // Same counter should not be regression
        assert!(!credential.has_counter_regression(10));

        // Higher counter should not be regression
        assert!(!credential.has_counter_regression(15));

        // Lower counter should be regression
        assert!(credential.has_counter_regression(5));
    }
}