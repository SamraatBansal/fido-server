//! Simplified FIDO/WebAuthn service implementation

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use url::Url;
use webauthn_rs::prelude::*;

use crate::config::settings::WebAuthnSettings;
use crate::db::{models::*, DbPool};
use crate::dto::*;
use crate::error::{AppError, Result};
use crate::schema::{challenges, credentials, users};
use crate::services::UserService;

/// Simple FIDO service for WebAuthn operations
#[derive(Clone)]
pub struct FidoService {
    webauthn: Webauthn,
    pool: DbPool,
    user_service: UserService,
}

/// Simple stored challenge data
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Uuid,
}

impl FidoService {
    /// Create a new FIDO service
    pub fn new(
        settings: &WebAuthnSettings,
        pool: DbPool,
        user_service: UserService,
    ) -> Result<Self> {
        let rp_origin = Url::parse(&settings.origin)
            .map_err(|e| AppError::ValidationError(format!("Invalid origin URL: {}", e)))?;

        let webauthn = WebauthnBuilder::new(&settings.rp_id, &rp_origin)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?
            .rp_name(&settings.rp_name)
            .build()
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(Self {
            webauthn,
            pool,
            user_service,
        })
    }

    /// Start passkey registration
    pub async fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Get or create user
        let user = self
            .user_service
            .get_or_create_user(&request.username, &request.display_name)
            .await?;

        // For now, implement a simple challenge generation
        let challenge = self.generate_challenge()?;
        
        // Store challenge
        self.store_challenge(user.id, &challenge, "registration").await?;

        // Create a simple response following the spec
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            server_response: ServerResponse::ok(),
            rp: PublicKeyCredentialRpEntity {
                id: Some("localhost".to_string()),
                name: "Example Corporation".to_string(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username.clone(),
                display_name: user.display_name.clone(),
            },
            challenge: URL_SAFE_NO_PAD.encode(&challenge),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    type_: "public-key".to_string(),
                    alg: -7, // ES256
                },
            ],
            timeout: Some(10000),
            exclude_credentials: Vec::new(),
            authenticator_selection: request.authenticator_selection.clone(),
            attestation: request.attestation.clone(),
            extensions: None,
        };

        Ok(response)
    }

    /// Finish passkey registration
    pub async fn finish_registration(
        &self,
        _request: &RegistrationResultRequest,
    ) -> Result<RegistrationResultResponse> {
        // For now, just return success - this will be a placeholder
        // In a real implementation, we would validate the attestation
        Ok(ServerResponse::ok())
    }

    /// Start passkey authentication
    pub async fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Find user
        let user = self
            .user_service
            .find_by_username(&request.username)
            .await?
            .ok_or_else(|| AppError::NotFound("User does not exists!".to_string()))?;

        // Generate challenge
        let challenge = self.generate_challenge()?;
        
        // Store challenge  
        self.store_challenge(user.id, &challenge, "authentication").await?;

        // Create simple response
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            server_response: ServerResponse::ok(),
            challenge: URL_SAFE_NO_PAD.encode(&challenge),
            timeout: Some(20000),
            rp_id: Some("localhost".to_string()),
            allow_credentials: Vec::new(), // Would include user's credentials in real implementation
            user_verification: request.user_verification.clone(),
            extensions: None,
        };

        Ok(response)
    }

    /// Finish passkey authentication
    pub async fn finish_authentication(
        &self,
        _request: &AuthenticationResultRequest,
    ) -> Result<AuthenticationResultResponse> {
        // For now, just return success - this will be a placeholder
        // In a real implementation, we would validate the assertion
        Ok(ServerResponse::ok())
    }

    /// Generate a cryptographically secure challenge
    fn generate_challenge(&self) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut challenge = vec![0u8; 32]; // 32 bytes = 256 bits
        rand::thread_rng().fill_bytes(&mut challenge);
        Ok(challenge)
    }

    /// Store challenge in database
    async fn store_challenge(
        &self,
        user_id: Uuid,
        challenge: &[u8],
        challenge_type: &str,
    ) -> Result<()> {
        let stored_challenge = StoredChallenge {
            challenge: challenge.to_vec(),
            user_id,
        };

        let challenge_data = serde_json::to_vec(&stored_challenge)?;

        let new_challenge = NewChallenge {
            user_id,
            challenge_type: challenge_type.to_string(),
            challenge_data,
            expires_at: Utc::now() + Duration::minutes(5),
        };

        let mut conn = self.pool.get()?;
        
        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)?;

        Ok(())
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<usize> {
        let mut conn = self.pool.get()?;
        
        let deleted = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        )
        .execute(&mut conn)?;

        Ok(deleted)
    }
}