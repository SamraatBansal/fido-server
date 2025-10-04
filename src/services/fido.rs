//! Core WebAuthn/FIDO service

use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::config::WebAuthnConfig;
use crate::db::models::{Credential, NewCredential, Session, User};
use crate::db::repositories::{CredentialRepository, SessionRepository};
use crate::error::{AppError, Result};

#[derive(Debug)]
pub struct RegistrationResult {
    pub credential_id: String,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct AuthenticationResult {
    pub user_id: Uuid,
    pub session_token: String,
}

pub struct FidoService {
    config: WebAuthnConfig,
    credential_repo: Arc<dyn CredentialRepository>,
    session_repo: Arc<dyn SessionRepository>,
}

impl FidoService {
    pub fn new(
        config: WebAuthnConfig,
        credential_repo: Arc<dyn CredentialRepository>,
        session_repo: Arc<dyn SessionRepository>,
    ) -> Self {
        Self {
            config,
            credential_repo,
            session_repo,
        }
    }

    /// Start registration process
    pub async fn start_registration(
        &self,
        user: &User,
        user_verification: Option<UserVerificationPolicy>,
    ) -> Result<CreationChallengeResponse> {
        let webauthn = self.config.build_webauthn()?;
        
        let webauthn_user = UserEntity {
            id: user.id.to_string(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
            credentials: vec![],
        };

        let uv = user_verification.unwrap_or(self.config.user_verification);
        
        let (ccr, _reg_state) = webauthn
            .start_registration(
                &webauthn_user,
                self.config.authenticator_attachment,
                uv,
                self.config.resident_key,
                None,
                Some(self.config.attestation_preference),
            )
            .map_err(AppError::WebAuthn)?;

        // Store registration state in session
        // TODO: Implement session storage for registration state

        Ok(ccr)
    }

    /// Finish registration process
    pub async fn finish_registration(
        &self,
        credential: &PublicKeyCredential,
        session_id: &str,
    ) -> Result<RegistrationResult> {
        let webauthn = self.config.build_webauthn()?;
        
        // TODO: Retrieve registration state from session
        // let reg_state = self.session_repo.find_by_id(&session_id).await?;
        
        // For now, we'll simulate the registration state
        // In a real implementation, this would be retrieved from the session
        
        // Verify attestation
        let auth_result = webauthn
            .finish_registration(&credential, /* reg_state */ &())
            .map_err(AppError::WebAuthn)?;

        // Extract credential data
        let credential_id = auth_result.cred_id().to_vec();
        let public_key = auth_result.public_key().to_vec();
        let sign_count = auth_result.counter() as i64;

        // Create new credential record
        let new_credential = NewCredential {
            user_id: Uuid::new_v4(), // TODO: Get from session
            credential_id,
            public_key,
            sign_count,
            attestation_format: Some("packed".to_string()), // TODO: Extract from attestation
            aaguid: None, // TODO: Extract from attestation
            transports: None, // TODO: Extract from credential
            backup_eligible: false, // TODO: Extract from credential
            backup_state: false, // TODO: Extract from credential
        };

        // Store credential
        let stored_credential = self
            .credential_repo
            .create_credential(&new_credential)
            .await?;

        // Clean up session
        // self.session_repo.delete_session(&session_id).await?;

        Ok(RegistrationResult {
            credential_id: base64::encode(stored_credential.credential_id),
            user_id: stored_credential.user_id,
        })
    }

    /// Start authentication process
    pub async fn start_authentication(
        &self,
        user: &User,
        user_verification: Option<UserVerificationPolicy>,
    ) -> Result<RequestChallengeResponse> {
        let webauthn = self.config.build_webauthn()?;
        
        // Get user's credentials
        let credentials = self.credential_repo.find_by_user_id(&user.id).await?;
        
        // Convert to PublicKeyCredentialDescriptor
        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred.credential_id,
                transports: None, // TODO: Use stored transports
            })
            .collect();

        if allow_credentials.is_empty() {
            return Err(AppError::AuthenticationFailed(
                "No credentials found for user".to_string(),
            ));
        }

        let uv = user_verification.unwrap_or(self.config.user_verification);

        let (acr, _auth_state) = webauthn
            .start_authentication(&allow_credentials, Some(uv))
            .map_err(AppError::WebAuthn)?;

        // TODO: Store authentication state in session

        Ok(acr)
    }

    /// Finish authentication process
    pub async fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        session_id: &str,
    ) -> Result<AuthenticationResult> {
        let webauthn = self.config.build_webauthn()?;
        
        // Find credential by ID
        let cred_id = credential.raw_id.as_slice();
        let stored_credential = self
            .credential_repo
            .find_by_credential_id(cred_id)
            .await?
            .ok_or(AppError::InvalidCredential("Credential not found".to_string()))?;

        // TODO: Retrieve authentication state from session
        
        // Verify assertion
        let auth_result = webauthn
            .finish_authentication(&credential, /* auth_state */ &())
            .map_err(AppError::WebAuthn)?;

        // Update sign count
        self.credential_repo
            .update_sign_count(&stored_credential.id, auth_result.counter() as i64)
            .await?;

        // Update last used timestamp
        self.credential_repo
            .update_last_used(&stored_credential.id)
            .await?;

        // Generate session token
        let session_token = self.generate_session_token(&stored_credential.user_id)?;

        // Clean up session
        // self.session_repo.delete_session(&session_id).await?;

        Ok(AuthenticationResult {
            user_id: stored_credential.user_id,
            session_token,
        })
    }

    fn generate_session_token(&self, user_id: &Uuid) -> Result<String> {
        // TODO: Implement proper JWT token generation
        // For now, return a simple token
        let token = format!("{}_{}", user_id, chrono::Utc::now().timestamp());
        Ok(base64::encode(token))
    }
}