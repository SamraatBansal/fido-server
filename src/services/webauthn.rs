//! WebAuthn service trait and implementation

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use std::sync::Arc;
use webauthn_rs::prelude::*;
use chrono::{DateTime, Utc, Duration};

use crate::schema::*;
use crate::services::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use crate::error::{Result, AppError};

/// WebAuthn service trait
#[async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn generate_registration_challenge(
        &self, 
        request: ServerPublicKeyCredentialCreationOptionsRequest
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;
    
    async fn verify_registration(
        &self, 
        credential: ServerPublicKeyCredential
    ) -> Result<ServerResponse>;
    
    async fn generate_authentication_challenge(
        &self, 
        request: ServerPublicKeyCredentialGetOptionsRequest
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;
    
    async fn verify_authentication(
        &self, 
        credential: ServerPublicKeyCredential
    ) -> Result<ServerResponse>;
}

/// WebAuthn service implementation
pub struct WebAuthnServiceImpl {
    webauthn: Webauthn<Config>,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    challenge_repo: Arc<dyn ChallengeRepository>,
}

impl WebAuthnServiceImpl {
    pub fn new(
        rp_id: &str,
        rp_name: &str,
        rp_origin: &str,
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        challenge_repo: Arc<dyn ChallengeRepository>,
    ) -> Result<Self> {
        let config = Config {
            rp: Rp {
                id: rp_id.to_string(),
                name: rp_name.to_string(),
            },
            origin: rp_origin.to_string(),
            ..Default::default()
        };

        let webauthn = WebAuthn::new(config);

        Ok(Self {
            webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
        })
    }
}

#[async_trait]
impl WebAuthnService for WebAuthnServiceImpl {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Find or create user
        let user = match self.user_repo.find_by_username(&request.username).await? {
            Some(user) => user,
            None => {
                let new_user = crate::db::models::NewUser {
                    username: request.username.clone(),
                    display_name: request.display_name.clone(),
                    email: None,
                };
                self.user_repo.create(&new_user).await?
            }
        };

        // Get existing credentials for excludeCredentials
        let credentials = self.credential_repo.find_by_user_id(user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials.into_iter().map(|cred| {
            ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            }
        }).collect();

        // Generate challenge
        let challenge_bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // Store challenge
        let expires_at = Utc::now() + Duration::minutes(5);
        let new_challenge = crate::db::models::NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "registration".to_string(),
            expires_at,
        };
        self.challenge_repo.create(&new_challenge).await?;

        // Build response
        let mut response = ServerPublicKeyCredentialCreationOptionsResponse::default();
        response.rp.name = "Example Corporation".to_string();
        response.user = ServerPublicKeyCredentialUserEntity {
            id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
            name: user.username,
            display_name: user.display_name,
        };
        response.challenge = challenge;
        response.exclude_credentials = Some(exclude_credentials);
        response.authenticator_selection = request.authenticator_selection;
        response.attestation = request.attestation.or(Some("none".to_string()));

        Ok(response)
    }

    async fn verify_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, just return success - we'll implement full verification later
        Ok(ServerResponse::success())
    }

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Find user
        let user = self.user_repo.find_by_username(&request.username).await?
            .ok_or_else(|| AppError::NotFound("User does not exists!".to_string()))?;

        // Get user's credentials
        let credentials = self.credential_repo.find_by_user_id(user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Build allowCredentials
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials.into_iter().map(|cred| {
            ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            }
        }).collect();

        // Generate challenge
        let challenge_bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // Store challenge
        let expires_at = Utc::now() + Duration::minutes(5);
        let new_challenge = crate::db::models::NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "authentication".to_string(),
            expires_at,
        };
        self.challenge_repo.create(&new_challenge).await?;

        // Build response
        let mut response = ServerPublicKeyCredentialGetOptionsResponse::default();
        response.challenge = challenge;
        response.allow_credentials = allow_credentials;
        response.user_verification = request.user_verification.or(Some("preferred".to_string()));

        Ok(response)
    }

    async fn verify_authentication(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, just return success - we'll implement full verification later
        Ok(ServerResponse::success())
    }
}