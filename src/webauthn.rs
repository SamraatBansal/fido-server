use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
use webauthn_rs_core::proto::{RelyingParty, RegistrationState, AuthenticationState};
use webauthn_rs_core::interface::{User, AuthenticationResult};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnUser {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub credentials: Vec<Passkey>,
}

impl WebAuthnUser {
    pub fn new(user_id: String, username: String, display_name: String) -> Self {
        Self {
            user_id,
            username,
            display_name,
            credentials: Vec::new(),
        }
    }
}

impl User for WebAuthnUser {
    fn get_id(&self) -> &[u8] {
        self.user_id.as_bytes()
    }

    fn get_name(&self) -> &str {
        &self.username
    }

    fn get_display_name(&self) -> &str {
        &self.display_name
    }
}

pub struct WebAuthnService {
    webauthn: Webauthn,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> Result<Self, WebauthnError> {
        let rp = RelyingParty {
            id: rp_id.to_string(),
            name: rp_name.to_string(),
            origin: Url::parse(rp_origin)
                .map_err(|_| WebauthnError::Configuration)?,
        };

        let webauthn = WebauthnBuilder::new(rp)?
            .build()?;

        Ok(WebAuthnService { webauthn })
    }

    pub fn begin_registration(
        &self,
        user: &WebAuthnUser,
    ) -> Result<CreationChallengeResponse, WebauthnError> {
        let (ccr, state) = self.webauthn.begin_registration(user)?;
        
        Ok(ccr)
    }

    pub fn finish_registration(
        &self,
        user: &mut WebAuthnUser,
        reg_response: &PublicKeyCredential,
        state: &RegistrationState,
    ) -> Result<Passkey, WebauthnError> {
        let passkey = self.webauthn.finish_registration(user, reg_response, state)?;
        user.credentials.push(passkey.clone());
        Ok(passkey)
    }

    pub fn begin_authentication(
        &self,
        user: &WebAuthnUser,
    ) -> Result<RequestChallengeResponse, WebauthnError> {
        let (acr, state) = self.webauthn.begin_authentication(user)?;
        Ok(acr)
    }

    pub fn finish_authentication(
        &self,
        user: &WebAuthnUser,
        auth_response: &PublicKeyCredential,
        state: &AuthenticationState,
    ) -> Result<AuthenticationResult, WebauthnError> {
        self.webauthn.finish_authentication(user, auth_response, state)
    }
}