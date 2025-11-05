use webauthn_rs::prelude::*;
use uuid::Uuid;

use crate::config::{AppConfig, WebAuthnConfig};
use crate::error::{AppError, AppResult};
use crate::models::User;

pub struct WebAuthnService {
    webauthn: Webauthn,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    pub fn new(config: &AppConfig) -> AppResult<Self> {
        let webauthn = WebauthnBuilder::new(&config.webauthn.rp_id, &config.webauthn.rp_origin)?
            .rp_name(&config.webauthn.rp_name)
            .build()?;
        
        Ok(Self {
            webauthn,
            config: config.webauthn.clone(),
        })
    }

    pub async fn start_passkey_registration(
        &self,
        user: &User,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> AppResult<(CreationChallengeResponse, PasskeyRegistration)> {
        let result = self.webauthn.start_passkey_registration(
            Uuid::from_bytes(user.user_id.as_slice().try_into().map_err(|_| {
                AppError::Internal {
                    message: "Invalid user ID format".to_string(),
                }
            })?),
            &user.username,
            &user.display_name,
            exclude_credentials,
        )?;
        
        Ok(result)
    }

    pub async fn finish_passkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> AppResult<Passkey> {
        let passkey = self.webauthn.finish_passkey_registration(reg, state)?;
        Ok(passkey)
    }

    pub async fn start_passkey_authentication(
        &self,
        allow_credentials: Vec<Passkey>,
    ) -> AppResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        let result = self.webauthn.start_passkey_authentication(&allow_credentials)?;
        Ok(result)
    }

    pub async fn finish_passkey_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> AppResult<AuthenticationResult> {
        let result = self.webauthn.finish_passkey_authentication(auth, state)?;
        Ok(result)
    }

    pub fn rp_id(&self) -> &str {
        &self.config.rp_id
    }

    pub fn rp_name(&self) -> &str {
        &self.config.rp_name
    }

    pub fn timeout_ms(&self) -> u32 {
        self.config.timeout_ms
    }
}