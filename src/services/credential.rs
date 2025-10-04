//! Credential management service

use uuid::Uuid;
use webauthn_rs::prelude::*;
use crate::db::{PooledDb, CredentialRepository, NewCredential, Credential};
use crate::error::{AppError, Result};
use base64::{Engine as _, engine::general_purpose};

/// Credential service for managing WebAuthn credentials
pub struct CredentialService {
    _db: std::marker::PhantomData<()>, // Placeholder for database connection
}

impl CredentialService {
    /// Create a new credential service
    pub fn new() -> Self {
        Self {
            _db: std::marker::PhantomData,
        }
    }

    /// Store a new credential from registration
    pub async fn store_credential(
        &self,
        conn: &mut PooledDb,
        auth_result: AuthenticatorRegistrationResult,
    ) -> Result<Credential> {
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.credential_id);
        
        // Extract AAGUID from attestation data if available
        let aaguid = self.extract_aaguid(&auth_result.attestation)?;
        
        let new_credential = NewCredential {
            user_id: auth_result.user_id,
            credential_id,
            public_key: serde_json::to_value(&auth_result.credential_public_key)
                .map_err(|e| AppError::InternalError(format!("Failed to serialize public key: {}", e)))?,
            sign_count: auth_result.counter as i64,
            aaguid,
            attestation_statement: auth_result.attestation
                .map(|a| serde_json::to_value(a).ok())
                .flatten(),
            backup_eligible: auth_result.backup_eligible,
            backup_state: auth_result.backup_state,
            clone_warning: auth_result.clone_warning,
        };

        CredentialRepository::create(conn, new_credential)
    }

    /// Get credential by credential ID string
    pub async fn get_credential_by_id(
        &self,
        conn: &mut PooledDb,
        credential_id: &str,
    ) -> Result<Option<Credential>> {
        CredentialRepository::find_by_credential_id(conn, credential_id)
    }

    /// Get all credentials for a user
    pub async fn get_user_credentials(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
    ) -> Result<Vec<Credential>> {
        CredentialRepository::find_by_user_id(conn, user_id)
    }

    /// Update credential usage after authentication
    pub async fn update_credential_usage(
        &self,
        conn: &mut PooledDb,
        credential_id: &[u8],
        counter: u32,
    ) -> Result<()> {
        let credential_id_str = general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
        
        // Get current credential to check for clone detection
        if let Some(credential) = CredentialRepository::find_by_credential_id(conn, &credential_id_str)? {
            // Check for potential clone if counter decreased
            if counter < credential.sign_count as u32 {
                log::warn!(
                    "Potential credential clone detected! Credential ID: {}, stored counter: {}, received counter: {}",
                    credential_id_str,
                    credential.sign_count,
                    counter
                );
                // In a production system, you might want to:
                // 1. Mark the credential as compromised
                // 2. Notify the user
                // 3. Require re-registration
            }
        }

        CredentialRepository::update_usage(conn, &credential_id_str, counter as i64)
    }

    /// Delete a credential
    pub async fn delete_credential(
        &self,
        conn: &mut PooledDb,
        credential_id: Uuid,
    ) -> Result<()> {
        CredentialRepository::delete(conn, credential_id)
    }

    /// Get credential for WebAuthn authentication
    pub async fn get_credential_for_auth(
        &self,
        conn: &mut PooledDb,
        credential_id: &CredentialID,
    ) -> Result<Option<AuthenticatorData>> {
        let credential_id_str = general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
        
        if let Some(credential) = CredentialRepository::find_by_credential_id(conn, &credential_id_str)? {
            // Convert stored public key back to AuthenticatorData
            let public_key: PublicKeyCredential = serde_json::from_value(credential.public_key)
                .map_err(|e| AppError::InternalError(format!("Failed to deserialize public key: {}", e)))?;
            
            // Create AuthenticatorData for webauthn-rs
            let auth_data = AuthenticatorData {
                credential_id: credential_id.clone(),
                public_key: public_key,
                sign_count: credential.sign_count as u32,
                user_present: true, // Assume user present for authentication
                user_verified: true, // Assume user verified for authentication
                backup_eligible: credential.backup_eligible,
                backup_state: credential.backup_state,
                extensions: Default::default(),
            };
            
            Ok(Some(auth_data))
        } else {
            Ok(None)
        }
    }

    /// Extract AAGUID from attestation data
    fn extract_aaguid(&self, attestation: &Option<AttestationFormat>) -> Result<Option<String>> {
        match attestation {
            Some(AttestationFormat::Packed(att)) => {
                // Extract AAGUID from packed attestation
                if let Some(auth_data) = att.authenticator_data.get(0..16) {
                    Ok(Some(general_purpose::URL_SAFE_NO_PAD.encode(auth_data)))
                } else {
                    Ok(None)
                }
            }
            Some(AttestationFormat::FidoU2F(_)) => {
                // FIDO U2F doesn't have AAGUID
                Ok(None)
            }
            Some(AttestationFormat::None) => {
                // No attestation, no AAGUID
                Ok(None)
            }
            _ => {
                // Other formats not yet implemented
                Ok(None)
            }
        }
    }

    /// Validate credential ID format
    fn validate_credential_id(&self, credential_id: &str) -> Result<()> {
        if credential_id.is_empty() {
            return Err(AppError::ValidationError("Credential ID cannot be empty".to_string()));
        }

        // Try to decode as base64url to validate format
        general_purpose::URL_SAFE_NO_PAD.decode(credential_id)
            .map_err(|_| AppError::ValidationError("Invalid credential ID format".to_string()))?;

        Ok(())
    }
}

impl Default for CredentialService {
    fn default() -> Self {
        Self::new()
    }
}