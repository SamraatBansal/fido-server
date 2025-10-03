//! WebAuthn service implementation

use crate::config::settings::WebAuthnSettings;
use crate::error::{AppError, Result};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// WebAuthn service wrapper
pub struct WebAuthnService {
    webauthn: Webauthn,
}

impl WebAuthnService {
    /// Create a new WebAuthn service instance
    ///
    /// # Errors
    ///
    /// Returns an error if WebAuthn configuration is invalid
    pub fn new(settings: &WebAuthnSettings) -> Result<Self> {
        let rp_id = &settings.rp_id;
        let rp_name = &settings.rp_name;
        let origin = url::Url::parse(&settings.origin)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid origin URL: {}", e)))?;

        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|e| {
                AppError::WebAuthnError(format!("Failed to create WebAuthn builder: {}", e))
            })?
            .rp_name(rp_name)
            .build()
            .map_err(|e| {
                AppError::WebAuthnError(format!("Failed to build WebAuthn instance: {}", e))
            })?;

        Ok(Self { webauthn })
    }

    /// Begin registration ceremony
    ///
    /// # Errors
    ///
    /// Returns an error if registration cannot be started
    pub fn begin_registration(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_uuid = Uuid::parse_str(user_id).unwrap_or_else(|_| Uuid::new_v4());

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_uuid, username, display_name, exclude_credentials)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to begin registration: {}", e)))?;

        Ok((ccr, reg_state))
    }

    /// Finish registration ceremony
    ///
    /// # Errors
    ///
    /// Returns an error if registration cannot be completed
    pub fn finish_registration(
        &self,
        reg_state: &PasskeyRegistration,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Passkey> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, reg_state)
            .map_err(|e| {
                AppError::WebAuthnError(format!("Failed to finish registration: {}", e))
            })?;

        Ok(passkey)
    }

    /// Begin authentication ceremony
    ///
    /// # Errors
    ///
    /// Returns an error if authentication cannot be started
    pub fn begin_authentication(
        &self,
        creds: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        let (acr, auth_state) = self
            .webauthn
            .start_passkey_authentication(creds)
            .map_err(|e| {
                AppError::WebAuthnError(format!("Failed to begin authentication: {}", e))
            })?;

        Ok((acr, auth_state))
    }

    /// Finish authentication ceremony
    ///
    /// # Errors
    ///
    /// Returns an error if authentication cannot be completed
    pub fn finish_authentication(
        &self,
        auth_state: &PasskeyAuthentication,
        response: &PublicKeyCredential,
    ) -> Result<AuthenticationResult> {
        let result = self
            .webauthn
            .finish_passkey_authentication(response, auth_state)
            .map_err(|e| {
                AppError::WebAuthnError(format!("Failed to finish authentication: {}", e))
            })?;

        Ok(result)
    }
}
