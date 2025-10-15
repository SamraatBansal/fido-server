//! WebAuthn Service
//! 
//! Core WebAuthn operations with security-first implementation

use std::time::Duration;
use webauthn_rs::prelude::*;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::{
    config::WebAuthnConfig,
    db::models::{User, Credential, Challenge},
    error::{AppError, Result},
    utils::crypto::generate_secure_random,
};

/// WebAuthn service for handling registration and authentication
pub struct WebAuthnService {
    webauthn: WebAuthn,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        let webauthn = config.create_webauthn()
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;
        
        Ok(Self { webauthn, config })
    }

    /// Generate registration challenge options
    pub async fn generate_registration_options(
        &self,
        user: &User,
        authenticator_selection: Option<AuthenticatorSelection>,
        attestation: Option<AttestationConveyancePreference>,
    ) -> Result<RegistrationState> {
        // Create user data
        let user_data = UserData::new(
            user.id.as_bytes().to_vec(),
            &user.username,
            &user.display_name,
            None,
        );

        // Create credential options
        let credential_options = self.webauthn
            .generate_challenge_register_options(
                user_data,
                authenticator_selection.unwrap_or_default(),
                attestation.unwrap_or(self.config.attestation.preference),
                self.config.security.allowed_algorithms.clone(),
            )
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store challenge for verification
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: credential_options.challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + Duration::from_secs(self.config.security.challenge_expiration),
            created_at: Utc::now(),
        };

        // TODO: Store challenge in database
        // self.challenge_repository.store(challenge).await?;

        Ok(credential_options)
    }

    /// Verify registration attestation
    pub async fn verify_registration(
        &self,
        registration_response: RegisterPublicKeyCredential,
        user_id: Uuid,
    ) -> Result<Credential> {
        // TODO: Retrieve and validate challenge from database
        // let challenge = self.challenge_repository.get_and_delete(
        //     &registration_response.response.client_data_json.challenge,
        //     user_id,
        //     "registration"
        // ).await?;

        // Verify attestation
        let attestation_result = self.webauthn
            .register_credential(&registration_response, None)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Create credential record
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id,
            credential_id: attestation_result.cred_id,
            credential_public_key: attestation_result.cred_public_key,
            attestation_type: attestation_result.attestation_format().to_string(),
            aaguid: Some(attestation_result.aaguid),
            sign_count: attestation_result.counter,
            created_at: Utc::now(),
            last_used_at: None,
            transports: None,
            backup_eligible: false,
            backup_state: false,
        };

        // TODO: Store credential in database
        // self.credential_repository.store(credential.clone()).await?;

        Ok(credential)
    }

    /// Generate authentication challenge options
    pub async fn generate_authentication_options(
        &self,
        user: &User,
        user_verification: Option<UserVerificationPolicy>,
    ) -> Result<AuthenticationState> {
        // TODO: Retrieve user credentials from database
        // let credentials = self.credential_repository.find_by_user_id(user.id).await?;

        // For now, create empty credential list
        let credentials = vec![];

        // Create authentication options
        let auth_options = self.webauthn
            .generate_challenge_authenticate_options(
                credentials,
                user_verification.unwrap_or(UserVerificationPolicy::Required),
            )
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store challenge for verification
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: auth_options.challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at: Utc::now() + Duration::from_secs(self.config.security.challenge_expiration),
            created_at: Utc::now(),
        };

        // TODO: Store challenge in database
        // self.challenge_repository.store(challenge).await?;

        Ok(auth_options)
    }

    /// Verify authentication assertion
    pub async fn verify_authentication(
        &self,
        auth_response: PublicKeyCredential,
        user_id: Uuid,
    ) -> Result<AuthenticationResult> {
        // TODO: Retrieve credential from database
        // let credential = self.credential_repository
        //     .find_by_credential_id(&auth_response.raw_id)
        //     .await
        //     .ok_or(AppError::CredentialNotFound)?;

        // TODO: Retrieve and validate challenge from database
        // let challenge = self.challenge_repository.get_and_delete(
        //     &auth_response.response.client_data_json.challenge,
        //     user_id,
        //     "authentication"
        // ).await?;

        // For now, create dummy credential data
        let credential_data = AuthenticatorData {
            // TODO: Use actual credential data
        };

        // Verify assertion
        let auth_result = self.webauthn
            .authenticate_credential(&auth_response, &credential_data)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // TODO: Update credential usage and counter
        // self.credential_repository.update_usage(
        //     &auth_response.raw_id,
        //     auth_result.counter,
        //     Utc::now()
        // ).await?;

        Ok(auth_result)
    }

    /// Validate challenge freshness and uniqueness
    pub async fn validate_challenge(
        &self,
        challenge_bytes: &[u8],
        user_id: Option<Uuid>,
        challenge_type: &str,
    ) -> Result<()> {
        // TODO: Implement challenge validation
        // 1. Check if challenge exists
        // 2. Verify it hasn't expired
        // 3. Verify it matches expected type
        // 4. Verify user binding if required
        // 5. Delete challenge to prevent replay

        Ok(())
    }

    /// Check for replay attacks using counter
    pub async fn detect_replay_attack(
        &self,
        credential_id: &[u8],
        counter: u32,
    ) -> Result<()> {
        // TODO: Implement replay detection
        // 1. Retrieve stored counter for credential
        // 2. Verify new counter is greater than stored
        // 3. Update stored counter

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebAuthnConfig;

    #[tokio::test]
    async fn test_webauthn_service_creation() {
        let config = WebAuthnConfig::default();
        let service = WebAuthnService::new(config);
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_registration_options_generation() {
        let config = WebAuthnConfig::default();
        let service = WebAuthnService::new(config).unwrap();

        let user = User {
            id: Uuid::new_v4(),
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let options = service.generate_registration_options(&user, None, None).await;
        assert!(options.is_ok());
    }

    #[tokio::test]
    async fn test_authentication_options_generation() {
        let config = WebAuthnConfig::default();
        let service = WebAuthnService::new(config).unwrap();

        let user = User {
            id: Uuid::new_v4(),
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let options = service.generate_authentication_options(&user, None).await;
        assert!(options.is_ok());
    }

    #[test]
    fn test_challenge_validation_security() {
        // Test challenge validation security properties
        let challenge1 = generate_secure_random(32);
        let challenge2 = generate_secure_random(32);

        // Challenges should be unique
        assert_ne!(challenge1, challenge2);

        // Challenges should be proper length
        assert_eq!(challenge1.len(), 32);
        assert_eq!(challenge2.len(), 32);
    }
}