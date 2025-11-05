use crate::db::models::NewChallenge;
use crate::db::repositories::ChallengeRepository;
use crate::error::{AppError, Result};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct ChallengeService {
    repository: Arc<ChallengeRepository>,
    ttl_minutes: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRegistrationChallenge {
    pub state: PasskeyRegistration,
    pub user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredAuthenticationChallenge {
    pub state: PasskeyAuthentication,
    pub username: String,
}

impl ChallengeService {
    pub fn new(repository: ChallengeRepository, ttl_minutes: i64) -> Self {
        Self {
            repository: Arc::new(repository),
            ttl_minutes,
        }
    }

    pub async fn store_registration_challenge(
        &self,
        user_id: Uuid,
        state: PasskeyRegistration,
    ) -> Result<String> {
        // Generate a random challenge ID for storage
        let challenge_id = self.generate_challenge_id();
        let expires_at = Utc::now() + Duration::minutes(self.ttl_minutes);

        let stored_challenge = StoredRegistrationChallenge { state, user_id };
        let challenge_data = serde_json::to_value(stored_challenge)?;

        let new_challenge = NewChallenge {
            id: challenge_id.clone(),
            user_id: Some(user_id),
            challenge_type: "registration".to_string(),
            challenge_data,
            expires_at,
        };

        self.repository.store_challenge(new_challenge).await?;
        Ok(challenge_id)
    }

    pub async fn store_authentication_challenge(
        &self,
        username: String,
        state: PasskeyAuthentication,
    ) -> Result<String> {
        // Use the actual challenge value as the ID for easier lookup
        let challenge_value = &state.challenge;
        let challenge_id = base64::encode_config(challenge_value, base64::URL_SAFE_NO_PAD);
        let expires_at = Utc::now() + Duration::minutes(self.ttl_minutes);

        let stored_challenge = StoredAuthenticationChallenge { state, username };
        let challenge_data = serde_json::to_value(stored_challenge)?;

        let new_challenge = NewChallenge {
            id: challenge_id.clone(),
            user_id: None, // Authentication challenges are not tied to specific users initially
            challenge_type: "authentication".to_string(),
            challenge_data,
            expires_at,
        };

        self.repository.store_challenge(new_challenge).await?;
        Ok(challenge_id)
    }

    pub async fn retrieve_and_remove_registration_challenge(
        &self,
        challenge_id: &str,
        user_id: Uuid,
    ) -> Result<PasskeyRegistration> {
        let challenge = self
            .repository
            .get_and_consume_challenge(challenge_id, Some(user_id))
            .await?
            .ok_or(AppError::ChallengeNotFound)?;

        if challenge.challenge_type != "registration" {
            return Err(AppError::validation("Invalid challenge type for registration"));
        }

        let stored_challenge: StoredRegistrationChallenge =
            serde_json::from_value(challenge.challenge_data)?;

        if stored_challenge.user_id != user_id {
            return Err(AppError::validation("Challenge user ID mismatch"));
        }

        Ok(stored_challenge.state)
    }

    pub async fn retrieve_and_remove_authentication_challenge(
        &self,
        challenge_id: &str,
        username: &str,
    ) -> Result<PasskeyAuthentication> {
        let challenge = self
            .repository
            .consume_challenge(challenge_id)
            .await?
            .ok_or(AppError::ChallengeNotFound)?;

        if challenge.challenge_type != "authentication" {
            return Err(AppError::validation("Invalid challenge type for authentication"));
        }

        let stored_challenge: StoredAuthenticationChallenge =
            serde_json::from_value(challenge.challenge_data)?;

        if stored_challenge.username != username {
            return Err(AppError::validation("Challenge username mismatch"));
        }

        Ok(stored_challenge.state)
    }

    pub async fn cleanup_expired_challenges(&self) -> Result<u64> {
        self.repository.cleanup_expired_challenges().await
    }

    pub async fn find_registration_challenge_by_value(
        &self,
        challenge_value: &str,
    ) -> Result<crate::db::models::Challenge> {
        // Convert challenge value to the stored ID format
        let challenge_id = base64::encode_config(challenge_value.as_bytes(), base64::URL_SAFE_NO_PAD);
        
        self.repository
            .get_challenge(&challenge_id)
            .await?
            .ok_or(AppError::ChallengeNotFound)
    }

    pub async fn find_authentication_challenge_by_value(
        &self,
        challenge_value: &str,
    ) -> Result<crate::db::models::Challenge> {
        // Convert challenge value to the stored ID format
        let challenge_id = base64::encode_config(challenge_value.as_bytes(), base64::URL_SAFE_NO_PAD);
        
        self.repository
            .get_challenge(&challenge_id)
            .await?
            .ok_or(AppError::ChallengeNotFound)
    }

    fn generate_challenge_id(&self) -> String {
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        base64::encode_config(random_bytes, base64::URL_SAFE_NO_PAD)
    }

    fn generate_challenge_id_from_value(&self, challenge: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        challenge.hash(&mut hasher);
        let hash = hasher.finish();
        
        format!("chal_{:x}", hash)
    }
}