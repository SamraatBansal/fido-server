use chrono::{Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::error::{AppError, AppResult};
use crate::models::{StoredChallenge, ChallengeType};
use crate::storage::Storage;

pub struct ChallengeService {
    pub storage: Arc<dyn Storage>,
}

impl ChallengeService {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    pub async fn store_registration_challenge(
        &self,
        user_id: Uuid,
        challenge: PasskeyRegistration,
    ) -> AppResult<String> {
        let challenge_id = self.generate_challenge_id();
        let challenge_data = serde_json::to_string(&challenge)?;
        
        let stored_challenge = StoredChallenge {
            id: challenge_id.clone(),
            user_id,
            challenge_type: ChallengeType::Registration,
            challenge_data,
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };

        self.storage.store_challenge(stored_challenge).await?;
        Ok(challenge_id)
    }

    pub async fn store_authentication_challenge(
        &self,
        user_id: Uuid,
        challenge: PasskeyAuthentication,
    ) -> AppResult<String> {
        let challenge_id = self.generate_challenge_id();
        let challenge_data = serde_json::to_string(&challenge)?;
        
        let stored_challenge = StoredChallenge {
            id: challenge_id.clone(),
            user_id,
            challenge_type: ChallengeType::Authentication,
            challenge_data,
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };

        self.storage.store_challenge(stored_challenge).await?;
        Ok(challenge_id)
    }

    pub async fn retrieve_and_remove_registration_challenge(
        &self,
        challenge_id: &str,
        user_id: Uuid,
    ) -> AppResult<PasskeyRegistration> {
        let challenge = self.storage.get_challenge(challenge_id).await?
            .ok_or(AppError::ChallengeNotFound)?;

        // Verify challenge belongs to the user
        if challenge.user_id != user_id {
            return Err(AppError::ChallengeNotFound);
        }

        // Verify challenge type
        if !matches!(challenge.challenge_type, ChallengeType::Registration) {
            return Err(AppError::ChallengeNotFound);
        }

        // Verify not expired
        if Utc::now() > challenge.expires_at {
            self.storage.remove_challenge(challenge_id).await?;
            return Err(AppError::ChallengeNotFound);
        }

        // Remove challenge (one-time use)
        self.storage.remove_challenge(challenge_id).await?;

        // Deserialize challenge data
        let registration_challenge: PasskeyRegistration = serde_json::from_str(&challenge.challenge_data)?;
        Ok(registration_challenge)
    }

    pub async fn retrieve_and_remove_authentication_challenge(
        &self,
        challenge_id: &str,
        user_id: Uuid,
    ) -> AppResult<PasskeyAuthentication> {
        let challenge = self.storage.get_challenge(challenge_id).await?
            .ok_or(AppError::ChallengeNotFound)?;

        // Verify challenge belongs to the user
        if challenge.user_id != user_id {
            return Err(AppError::ChallengeNotFound);
        }

        // Verify challenge type
        if !matches!(challenge.challenge_type, ChallengeType::Authentication) {
            return Err(AppError::ChallengeNotFound);
        }

        // Verify not expired
        if Utc::now() > challenge.expires_at {
            self.storage.remove_challenge(challenge_id).await?;
            return Err(AppError::ChallengeNotFound);
        }

        // Remove challenge (one-time use)
        self.storage.remove_challenge(challenge_id).await?;

        // Deserialize challenge data
        let auth_challenge: PasskeyAuthentication = serde_json::from_str(&challenge.challenge_data)?;
        Ok(auth_challenge)
    }

    pub async fn cleanup_expired_challenges(&self) -> AppResult<()> {
        self.storage.cleanup_expired_challenges().await
    }

    pub async fn store_challenge_to_user_mapping(&self, challenge_key: &str, user_id: Uuid) -> AppResult<()> {
        // Store a temporary mapping from challenge value to user ID
        // This allows us to look up the user when processing the result
        let mapping_challenge = StoredChallenge {
            id: format!("mapping_{}", challenge_key),
            user_id,
            challenge_type: ChallengeType::Registration, // doesn't matter for mappings
            challenge_data: user_id.to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
        };
        self.storage.store_challenge(mapping_challenge).await
    }

    pub async fn get_user_by_challenge_value(&self, challenge_value: &str) -> AppResult<Option<Uuid>> {
        let mapping_id = format!("mapping_{}", challenge_value);
        if let Some(mapping) = self.storage.get_challenge(&mapping_id).await? {
            if Utc::now() <= mapping.expires_at {
                return Ok(Some(mapping.user_id));
            }
        }
        Ok(None)
    }

    fn generate_challenge_id(&self) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}