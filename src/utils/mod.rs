use crate::config::Settings;
use crate::db::{create_pool, ChallengeRepository, CredentialRepository, UserRepository};
use crate::services::WebAuthnService;
use crate::Result;

#[derive(Clone)]
pub struct AppState {
    pub webauthn_service: WebAuthnService,
}

impl AppState {
    pub fn new(settings: &Settings) -> Result<Self> {
        let pool = create_pool(&settings.database)?;
        
        let user_repo = UserRepository::new(pool.clone());
        let credential_repo = CredentialRepository::new(pool.clone());
        let challenge_repo = ChallengeRepository::new(pool.clone());
        
        let webauthn_service = WebAuthnService::new(
            &settings.webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
        )?;
        
        Ok(Self {
            webauthn_service,
        })
    }
}