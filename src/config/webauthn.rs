//! WebAuthn-specific configuration and utilities

use crate::config::WebAuthnConfig;
use webauthn_rs::prelude::*;
use webauthn_rs::WebAuthn;

/// WebAuthn context containing the WebAuthn instance and configuration
#[derive(Clone)]
pub struct WebAuthnContext {
    /// WebAuthn instance
    pub webauthn: WebAuthn,
    /// Configuration
    pub config: WebAuthnConfig,
}

impl WebAuthnContext {
    /// Create new WebAuthn context from configuration
    pub fn new(config: WebAuthnConfig) -> Result<Self, webauthn_rs::error::WebauthnError> {
        let webauthn = config.create_webauthn()?;
        Ok(Self { webauthn, config })
    }

    /// Get credential creation options for registration
    pub fn registration_options(
        &self,
        user: &WebauthnUser,
        exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    ) -> Result<PublicKeyCredentialCreationOptions, webauthn_rs::error::WebauthnError> {
        let mut options = self.webauthn.start_registration(
            user,
            self.config.user_verification,
            self.config.attestation_preference,
            exclude_credentials,
        )?;

        options.timeout = Some(self.config.timeout);
        Ok(options)
    }

    /// Get credential request options for authentication
    pub fn authentication_options(
        &self,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    ) -> Result<PublicKeyCredentialRequestOptions, webauthn_rs::error::WebauthnError> {
        let mut options = self.webauthn.start_authentication(
            allow_credentials,
            self.config.user_verification,
        )?;

        options.timeout = Some(self.config.timeout);
        Ok(options)
    }

    /// Verify registration attestation
    pub fn verify_registration(
        &self,
        reg: &PublicKeyCredential,
        state: &RegistrationState,
    ) -> Result<WebauthnResult, webauthn_rs::error::WebauthnError> {
        self.webauthn.finish_registration(reg, state)
    }

    /// Verify authentication assertion
    pub fn verify_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &AuthenticationState,
    ) -> Result<AuthenticatorResult, webauthn_rs::error::WebauthnError> {
        self.webauthn.finish_authentication(auth, state)
    }
}

/// WebAuthn user implementation
#[derive(Debug, Clone)]
pub struct WebauthnUser {
    /// User ID
    pub id: Vec<u8>,
    /// Username
    pub name: String,
    /// Display name
    pub display_name: String,
    /// Credentials associated with this user
    pub credentials: Vec<WebauthnCredential>,
}

impl WebauthnUser {
    /// Create new WebAuthn user
    pub fn new(
        id: Vec<u8>,
        name: String,
        display_name: String,
        credentials: Vec<WebauthnCredential>,
    ) -> Self {
        Self {
            id,
            name,
            display_name,
            credentials,
        }
    }

    /// Add credential to user
    pub fn add_credential(&mut self, credential: WebauthnCredential) {
        self.credentials.push(credential);
    }

    /// Remove credential from user
    pub fn remove_credential(&mut self, credential_id: &[u8]) -> bool {
        let initial_len = self.credentials.len();
        self.credentials.retain(|cred| cred.cred_id != credential_id);
        self.credentials.len() < initial_len
    }

    /// Get credential by ID
    pub fn get_credential(&self, credential_id: &[u8]) -> Option<&WebauthnCredential> {
        self.credentials.iter().find(|cred| cred.cred_id == credential_id)
    }

    /// Get credential descriptors for authentication
    pub fn get_credential_descriptors(&self) -> Vec<PublicKeyCredentialDescriptor> {
        self.credentials
            .iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                type_: cred.cred_type.clone(),
                id: cred.cred_id.clone(),
                transports: Some(cred.transports.clone()),
            })
            .collect()
    }
}

impl webauthn_rs::prelude::WebauthnUser for WebauthnUser {
    fn get_id(&self) -> &[u8] {
        &self.id
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_display_name(&self) -> &str {
        &self.display_name
    }

    fn get_credential_ids(&self) -> Vec<&[u8]> {
        self.credentials.iter().map(|cred| cred.cred_id.as_slice()).collect()
    }

    fn get_credentials(&self) -> Vec<webauthn_rs::prelude::Credential> {
        self.credentials
            .iter()
            .map(|cred| webauthn_rs::prelude::Credential {
                cred_id: cred.cred_id.clone(),
                cred: cred.cred.clone(),
                counter: cred.counter,
                transports: cred.transports.clone(),
            })
            .collect()
    }
}

/// WebAuthn credential representation
#[derive(Debug, Clone)]
pub struct WebauthnCredential {
    /// Credential ID
    pub cred_id: Vec<u8>,
    /// Credential type
    pub cred_type: String,
    /// Credential data
    pub cred: webauthn_rs::prelude::CredentialData,
    /// Signature counter
    pub counter: u32,
    /// Transport methods
    pub transports: Vec<AuthenticatorTransport>,
    /// Attestation type
    pub attestation_type: String,
    /// AAGUID
    pub aaguid: Vec<u8>,
    /// Backup eligible
    pub backup_eligible: bool,
    /// Backed up
    pub backed_up: bool,
}

impl WebauthnCredential {
    /// Create new credential from registration result
    pub fn from_registration_result(
        result: &WebauthnResult,
        transports: Vec<AuthenticatorTransport>,
    ) -> Self {
        Self {
            cred_id: result.cred_id.clone(),
            cred_type: "public-key".to_string(),
            cred: result.cred.clone(),
            counter: result.counter,
            transports,
            attestation_type: result.attestation_type().to_string(),
            aaguid: result.aaguid.clone(),
            backup_eligible: result.backup_eligible,
            backed_up: result.backed_up,
        }
    }

    /// Update counter from authentication result
    pub fn update_counter(&mut self, new_counter: u32) {
        self.counter = new_counter;
    }

    /// Check if credential is backed up
    pub fn is_backed_up(&self) -> bool {
        self.backed_up
    }

    /// Check if credential is backup eligible
    pub fn is_backup_eligible(&self) -> bool {
        self.backup_eligible
    }
}

/// Challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// Registration challenge
    Registration,
    /// Authentication challenge
    Authentication,
}

impl ChallengeType {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Registration => "registration",
            ChallengeType::Authentication => "authentication",
        }
    }

    /// Convert from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "registration" => Some(ChallengeType::Registration),
            "authentication" => Some(ChallengeType::Authentication),
            _ => None,
        }
    }
}

/// Challenge data
#[derive(Debug, Clone)]
pub struct ChallengeData {
    /// Challenge value
    pub challenge: String,
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// User ID (optional for authentication)
    pub user_id: Option<Vec<u8>>,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ChallengeData {
    /// Create new challenge
    pub fn new(
        challenge: String,
        challenge_type: ChallengeType,
        user_id: Option<Vec<u8>>,
        ttl_seconds: i64,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            challenge,
            challenge_type,
            user_id,
            expires_at: now + chrono::Duration::seconds(ttl_seconds),
            created_at: now,
        }
    }

    /// Check if challenge is expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Get remaining time until expiration
    pub fn remaining_time(&self) -> chrono::Duration {
        self.expires_at - chrono::Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_challenge_type() {
        assert_eq!(ChallengeType::Registration.as_str(), "registration");
        assert_eq!(ChallengeType::Authentication.as_str(), "authentication");
        assert_eq!(ChallengeType::from_str("registration"), Some(ChallengeType::Registration));
        assert_eq!(ChallengeType::from_str("invalid"), None);
    }

    #[test]
    fn test_challenge_data() {
        let challenge = ChallengeData::new(
            "test-challenge".to_string(),
            ChallengeType::Registration,
            Some(b"user123".to_vec()),
            300,
        );

        assert_eq!(challenge.challenge, "test-challenge");
        assert_eq!(challenge.challenge_type, ChallengeType::Registration);
        assert_eq!(challenge.user_id, Some(b"user123".to_vec()));
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_webauthn_user() {
        let user = WebauthnUser::new(
            b"user123".to_vec(),
            "testuser".to_string(),
            "Test User".to_string(),
            vec![],
        );

        assert_eq!(user.get_id(), b"user123");
        assert_eq!(user.get_name(), "testuser");
        assert_eq!(user.get_display_name(), "Test User");
        assert!(user.get_credential_ids().is_empty());
    }
}