//! Core WebAuthn service implementation

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use rand::{thread_rng, RngCore};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::config::WebAuthnSettings;
use crate::db::{DbPool, NewChallenge, NewCredential, UpdateChallenge, UpdateCredential};
use crate::error::{AppError, Result};
use crate::schema::{challenges, credentials, users};

/// Trait for challenge storage operations
#[async_trait::async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn store_challenge(&self, challenge: &NewChallenge) -> Result<()>;
    async fn get_and_consume_challenge(&self, challenge_bytes: &[u8]) -> Result<Option<Challenge>>;
    async fn cleanup_expired_challenges(&self) -> Result<usize>;
}

/// Trait for credential storage operations
#[async_trait::async_trait]
pub trait CredentialStore: Send + Sync {
    async fn store_credential(&self, credential: &NewCredential) -> Result<()>;
    async fn get_credentials_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    async fn update_credential(&self, credential_id: &[u8], update: UpdateCredential) -> Result<()>;
    async fn delete_credential(&self, credential_id: &[u8]) -> Result<()>;
}

/// Core WebAuthn service
pub struct WebAuthnService {
    webauthn: WebAuthn<WebAuthnConfig>,
    config: WebAuthnSettings,
    pool: Arc<DbPool>,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    ///
    /// # Arguments
    ///
    /// * `config` - WebAuthn configuration
    /// * `pool` - Database connection pool
    ///
    /// # Errors
    ///
    /// Returns an error if WebAuthn configuration is invalid
    pub fn new(config: WebAuthnSettings, pool: Arc<DbPool>) -> Result<Self> {
        let webauthn_config = WebAuthnConfig {
            rp: Rp {
                id: config.rp_id.clone(),
                name: config.rp_name.clone(),
                origin: Url::parse(&config.origin)
                    .map_err(|e| AppError::WebAuthn(format!("Invalid origin URL: {}", e)))?,
            },
        };

        let webauthn = WebAuthn::new(webauthn_config);

        Ok(Self {
            webauthn,
            config,
            pool,
        })
    }

    /// Generate a cryptographically secure challenge
    fn generate_challenge(&self) -> Result<Vec<u8>> {
        let mut challenge = vec![0u8; 32];
        thread_rng().fill_bytes(&mut challenge);
        Ok(challenge)
    }

    /// Start registration flow
    ///
    /// # Arguments
    ///
    /// * `username` - User's username
    /// * `display_name` - User's display name
    ///
    /// # Errors
    ///
    /// Returns an error if registration cannot be started
    pub async fn start_registration(
        &self,
        username: &str,
        display_name: &str,
    ) -> Result<PublicKeyCredentialCreationOptions> {
        // Generate challenge
        let challenge_bytes = self.generate_challenge()?;
        let challenge = BASE64.encode(&challenge_bytes);

        // Create user entity
        let user = User {
            id: BASE64.encode(&Uuid::new_v4().as_bytes()),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        // Generate registration options
        let options = self.webauthn.generate_challenge_register_options(
            user,
            &challenge,
            Some(AttestationConveyancePreference::Direct),
            Some(UserVerificationPolicy::Required),
            Some(ResidentKeyRequirement::Preferred),
        )
        .map_err(|e| AppError::WebAuthn(format!("Failed to generate registration options: {}", e)))?;

        // Store challenge
        let expires_at = Utc::now() + Duration::seconds(self.config.challenge_ttl_seconds as i64);
        let new_challenge = NewChallenge {
            challenge_bytes,
            challenge_type: "registration".to_string(),
            user_id: None, // Will be set after user creation
            expires_at,
        };

        let mut conn = self.pool.get()?;
        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to store challenge: {}", e)))?;

        Ok(options)
    }

    /// Finish registration flow
    ///
    /// # Arguments
    ///
    /// * `attestation_response` - Registration attestation response
    ///
    /// # Errors
    ///
    /// Returns an error if registration cannot be completed
    pub async fn finish_registration(
        &self,
        attestation_response: &PublicKeyCredential<AttestationResponse>,
    ) -> Result<()> {
        // Extract and validate challenge
        let client_data_json = &attestation_response.response.client_data_json;
        let client_data: CollectedClientData = serde_json::from_str(client_data_json)
            .map_err(|e| AppError::WebAuthn(format!("Invalid client data JSON: {}", e)))?;

        let challenge_bytes = BASE64
            .decode(client_data.challenge.as_str())
            .map_err(|e| AppError::WebAuthn(format!("Invalid challenge encoding: {}", e)))?;

        // Get and consume challenge
        let mut conn = self.pool.get()?;
        let challenge: Challenge = challenges::table
            .filter(challenges::challenge_bytes.eq(&challenge_bytes))
            .filter(challenges::challenge_type.eq("registration"))
            .filter(challenges::used.eq(false))
            .filter(challenges::expires_at.gt(Utc::now()))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(format!("Failed to fetch challenge: {}", e)))?
            .ok_or(AppError::ChallengeNotFound)?;

        // Mark challenge as used
        diesel::update(challenges::table.find(challenge.id))
            .set(&UpdateChallenge { used: Some(true) })
            .execute(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to update challenge: {}", e)))?;

        // Verify attestation
        let verification_result = self.webauthn.verify_attestation(
            attestation_response,
            &self.webauthn.rp,
        )
        .map_err(|e| AppError::WebAuthn(format!("Attestation verification failed: {}", e)))?;

        // Create or get user
        let user_id = self.get_or_create_user(
            &attestation_response.response.user.id,
            &attestation_response.response.user.name,
            &attestation_response.response.user.display_name,
        )?;

        // Store credential
        let credential_data = verification_result.credential_data();
        let new_credential = NewCredential {
            user_id,
            credential_id: credential_data.cred_id.clone(),
            credential_public_key: credential_data.public_key.clone(),
            attestation_format: verification_result.attestation_format().to_string(),
            aaguid: credential_data.aaguid,
            sign_count: verification_result.counter() as i64,
            user_verification: verification_result.user_verified(),
            backup_eligible: credential_data.backup_eligible,
            backup_state: credential_data.backup_state,
            transports: Some(credential_data.transports.iter().map(|t| t.to_string()).collect()),
        };

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to store credential: {}", e)))?;

        Ok(())
    }

    /// Start authentication flow
    ///
    /// # Arguments
    ///
    /// * `username` - User's username
    ///
    /// # Errors
    ///
    /// Returns an error if authentication cannot be started
    pub async fn start_authentication(&self, username: &str) -> Result<PublicKeyCredentialRequestOptions> {
        // Generate challenge
        let challenge_bytes = self.generate_challenge()?;
        let challenge = BASE64.encode(&challenge_bytes);

        // Get user and their credentials
        let mut conn = self.pool.get()?;
        let user: User = users::table
            .filter(users::username.eq(username))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(format!("Failed to fetch user: {}", e)))?
            .ok_or(AppError::UserNotFound)?;

        let user_credentials: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user.id))
            .load(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to fetch credentials: {}", e)))?;

        if user_credentials.is_empty() {
            return Err(AppError::InvalidCredential);
        }

        // Convert credentials to allow_credentials format
        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = user_credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64.encode(&cred.credential_id),
                transports: cred.transports.unwrap_or_default(),
            })
            .collect();

        // Generate authentication options
        let options = self.webauthn.generate_challenge_authenticate_options(
            allow_credentials,
            Some(UserVerificationPolicy::Required),
            &challenge,
        )
        .map_err(|e| AppError::WebAuthn(format!("Failed to generate authentication options: {}", e)))?;

        // Store challenge
        let expires_at = Utc::now() + Duration::seconds(self.config.challenge_ttl_seconds as i64);
        let new_challenge = NewChallenge {
            challenge_bytes,
            challenge_type: "authentication".to_string(),
            user_id: Some(user.id),
            expires_at,
        };

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to store challenge: {}", e)))?;

        Ok(options)
    }

    /// Finish authentication flow
    ///
    /// # Arguments
    ///
    /// * `assertion_response` - Authentication assertion response
    ///
    /// # Errors
    ///
    /// Returns an error if authentication cannot be completed
    pub async fn finish_authentication(
        &self,
        assertion_response: &PublicKeyCredential<AssertionResponse>,
    ) -> Result<()> {
        // Extract and validate challenge
        let client_data_json = &assertion_response.response.client_data_json;
        let client_data: CollectedClientData = serde_json::from_str(client_data_json)
            .map_err(|e| AppError::WebAuthn(format!("Invalid client data JSON: {}", e)))?;

        let challenge_bytes = BASE64
            .decode(client_data.challenge.as_str())
            .map_err(|e| AppError::WebAuthn(format!("Invalid challenge encoding: {}", e)))?;

        // Get and consume challenge
        let mut conn = self.pool.get()?;
        let challenge: Challenge = challenges::table
            .filter(challenges::challenge_bytes.eq(&challenge_bytes))
            .filter(challenges::challenge_type.eq("authentication"))
            .filter(challenges::used.eq(false))
            .filter(challenges::expires_at.gt(Utc::now()))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(format!("Failed to fetch challenge: {}", e)))?
            .ok_or(AppError::ChallengeNotFound)?;

        // Mark challenge as used
        diesel::update(challenges::table.find(challenge.id))
            .set(&UpdateChallenge { used: Some(true) })
            .execute(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to update challenge: {}", e)))?;

        // Get credential
        let credential_id = BASE64
            .decode(&assertion_response.raw_id)
            .map_err(|e| AppError::WebAuthn(format!("Invalid credential ID encoding: {}", e)))?;

        let credential: Credential = credentials::table
            .filter(credentials::credential_id.eq(&credential_id))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(format!("Failed to fetch credential: {}", e)))?
            .ok_or(AppError::InvalidCredential)?;

        // Verify assertion
        let verification_result = self.webauthn.verify_assertion(
            assertion_response,
            &credential.credential_public_key,
            credential.sign_count as u32,
        )
        .map_err(|e| AppError::WebAuthn(format!("Assertion verification failed: {}", e)))?;

        // Update credential
        let update_credential = UpdateCredential {
            sign_count: Some(verification_result.counter() as i64),
            last_used_at: Some(Utc::now()),
            backup_state: None, // Keep existing backup state
        };

        diesel::update(credentials::table.find(credential.id))
            .set(&update_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(format!("Failed to update credential: {}", e)))?;

        Ok(())
    }

    /// Get or create user
    fn get_or_create_user(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
    ) -> Result<Uuid> {
        use crate::db::NewUser;
        
        let mut conn = self.pool.get()?;
        
        // Try to find existing user by username
        let existing_user: Option<User> = users::table
            .filter(users::username.eq(username))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(format!("Failed to fetch user: {}", e)))?;

        if let Some(user) = existing_user {
            Ok(user.id)
        } else {
            // Create new user
            let new_user = NewUser {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };

            let user: User = diesel::insert_into(users::table)
                .values(&new_user)
                .get_result(&mut conn)
                .map_err(|e| AppError::Database(format!("Failed to create user: {}", e)))?;

            Ok(user.id)
        }
    }

    /// Cleanup expired challenges
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails
    pub async fn cleanup_expired_challenges(&self) -> Result<usize> {
        let mut conn = self.pool.get()?;
        
        let deleted_count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        )
        .execute(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to cleanup challenges: {}", e)))?;

        Ok(deleted_count)
    }
}

// Import the required models
use crate::db::{User, Credential, Challenge};