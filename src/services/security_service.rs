//! Security service implementation

use std::sync::Arc;
use crate::db::repositories::ChallengeRepository;
use crate::models::{StoredChallenge, ChallengeType};
use crate::error::{AppError, Result};

/// Security service
pub struct SecurityService {
    challenge_repo: Arc<dyn ChallengeRepository>,
}

impl SecurityService {
    /// Create a new security service
    pub fn new(challenge_repo: Arc<dyn ChallengeRepository>) -> Self {
        Self { challenge_repo }
    }

    /// Generate a secure random challenge
    pub fn generate_challenge() -> Result<String> {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        Ok(base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD))
    }

    /// Store challenge
    pub async fn store_challenge(&self, challenge: &StoredChallenge) -> Result<()> {
        self.challenge_repo.store_challenge(challenge).await
    }

    /// Get challenge
    pub async fn get_challenge(&self, challenge: &str, challenge_type: ChallengeType) -> Result<Option<StoredChallenge>> {
        self.challenge_repo.get_challenge(challenge, challenge_type).await
    }

    /// Consume challenge (get and delete)
    pub async fn consume_challenge(&self, challenge: &str, challenge_type: ChallengeType) -> Result<Option<StoredChallenge>> {
        self.challenge_repo.consume_challenge(challenge, challenge_type).await
    }

    /// Cleanup expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<u64> {
        self.challenge_repo.cleanup_expired_challenges().await
    }

    /// Validate challenge format and length
    pub fn validate_challenge(challenge: &str) -> Result<()> {
        if challenge.is_empty() {
            return Err(AppError::InvalidInput("Challenge cannot be empty".to_string()));
        }
        
        if challenge.len() < 16 {
            return Err(AppError::InvalidInput("Challenge too short".to_string()));
        }
        
        if challenge.len() > 64 {
            return Err(AppError::InvalidInput("Challenge too long".to_string()));
        }

        // Verify it's valid base64url
        base64::decode_config(challenge, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidInput("Invalid challenge format".to_string()))?;

        Ok(())
    }

    /// Validate RP ID against origin
    pub fn validate_rp_id(rp_id: &str, origin: &str) -> Result<()> {
        // Parse origin to get hostname
        let origin_url = url::Url::parse(origin)
            .map_err(|_| AppError::InvalidInput("Invalid origin format".to_string()))?;
        
        let origin_host = origin_url.host_str()
            .ok_or_else(|| AppError::InvalidInput("Invalid origin host".to_string()))?;

        // Check if RP ID is a registrable domain suffix of the origin
        if origin_host == rp_id {
            return Ok(());
        }

        // Check if origin ends with RP ID with a dot prefix
        let rp_id_with_dot = format!(".{}", rp_id);
        if origin_host.ends_with(&rp_id_with_dot) {
            return Ok(());
        }

        Err(AppError::InvalidInput("RP ID validation failed".to_string()))
    }
}