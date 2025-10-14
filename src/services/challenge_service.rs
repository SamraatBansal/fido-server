//! Challenge management service

use crate::error::{AppError, Result};
use crate::models::{Challenge, ChallengeType};
use crate::repositories::ChallengeRepository;
use crate::services::CryptoService;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub trait ChallengeServiceTrait: Send + Sync {
    async fn generate_challenge(&self, user_id: Option<Uuid>, challenge_type: ChallengeType) -> Result<String>;
    async fn verify_challenge(&self, challenge: &str, user_id: Option<Uuid>, challenge_type: ChallengeType) -> Result<()>;
    async fn cleanup_expired_challenges(&self) -> Result<u64>;
}

pub struct ChallengeService {
    challenge_repository: Arc<dyn ChallengeRepository>,
    crypto_service: Arc<dyn CryptoService>,
}

impl ChallengeService {
    pub fn new(
        challenge_repository: Arc<dyn ChallengeRepository>,
        crypto_service: Arc<dyn CryptoService>,
    ) -> Self {
        Self {
            challenge_repository,
            crypto_service,
        }
    }

    fn decode_challenge(&self, challenge: &str) -> Result<Vec<u8>> {
        base64::decode_config(challenge, base64::URL_SAFE_NO_PAD)
            .map_err(|e| AppError::InvalidInput(format!("Invalid challenge encoding: {}", e)))
    }
}

#[async_trait]
impl ChallengeServiceTrait for ChallengeService {
    async fn generate_challenge(&self, user_id: Option<Uuid>, challenge_type: ChallengeType) -> Result<String> {
        // Generate 32-byte random challenge
        let challenge_bytes = self.crypto_service.generate_secure_random(32)?;
        
        // Hash the challenge for storage
        let challenge_hash = self.crypto_service.hash_challenge(&challenge_bytes)?;
        
        // Create challenge entity with 5-minute expiration
        let challenge_entity = Challenge::new(challenge_hash, user_id, challenge_type, 5)?;
        
        // Store challenge
        self.challenge_repository.create_challenge(&challenge_entity).await?;
        
        // Return base64url-encoded challenge
        Ok(base64::encode_config(challenge_bytes, base64::URL_SAFE_NO_PAD))
    }

    async fn verify_challenge(&self, challenge: &str, user_id: Option<Uuid>, challenge_type: ChallengeType) -> Result<()> {
        // Decode challenge
        let challenge_bytes = self.decode_challenge(challenge)?;
        
        // Hash the decoded challenge
        let challenge_hash = self.crypto_service.hash_challenge(&challenge_bytes)?;
        
        // Look up challenge in database
        let stored_challenge = self.challenge_repository
            .get_challenge_by_hash(&challenge_hash, user_id.as_ref(), &challenge_type)
            .await?
            .ok_or(AppError::InvalidChallenge)?;
        
        // Check if challenge is still valid
        if !stored_challenge.is_valid() {
            return if stored_challenge.is_expired() {
                Err(AppError::ChallengeExpired)
            } else {
                Err(AppError::InvalidChallenge)
            };
        }
        
        // Mark challenge as used
        self.challenge_repository.mark_challenge_used(&stored_challenge.id).await?;
        
        Ok(())
    }

    async fn cleanup_expired_challenges(&self) -> Result<u64> {
        self.challenge_repository.cleanup_expired_challenges().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::ChallengeRepository;
    use crate::services::CryptoService;
    use mockall::mock;
    use uuid::Uuid;

    mock! {
        ChallengeRepo {}

        #[async_trait]
        impl ChallengeRepository for ChallengeRepo {
            async fn create_challenge(&self, challenge: &Challenge) -> Result<()>;
            async fn get_challenge_by_hash(&self, challenge_hash: &[u8], user_id: Option<&Uuid>, challenge_type: &ChallengeType) -> Result<Option<Challenge>>;
            async fn mark_challenge_used(&self, challenge_id: &Uuid) -> Result<()>;
            async fn cleanup_expired_challenges(&self) -> Result<u64>;
        }
    }

    mock! {
        Crypto {}

        impl CryptoService for Crypto {
            fn generate_secure_random(&self, length: usize) -> Result<Vec<u8>>;
            fn hash_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>>;
            fn verify_challenge_hash(&self, challenge: &[u8], hash: &[u8]) -> Result<bool>;
        }
    }

    #[tokio::test]
    async fn test_generate_challenge_success() {
        let mut mock_repo = MockChallengeRepo::new();
        let mut mock_crypto = MockCrypto::new();
        
        let challenge_bytes = vec![1u8; 32];
        let challenge_hash = vec![2u8; 32];
        
        mock_crypto
            .expect_generate_secure_random()
            .returning(|_| Ok(vec![1u8; 32]));
        
        mock_crypto
            .expect_hash_challenge()
            .returning(|_| Ok(vec![2u8; 32]));
        
        mock_repo
            .expect_create_challenge()
            .returning(|_| Ok(()));
        
        let service = ChallengeService::new(
            Arc::new(mock_repo),
            Arc::new(mock_crypto),
        );
        
        let result = service.generate_challenge(None, ChallengeType::Registration).await;
        assert!(result.is_ok());
        
        let challenge = result.unwrap();
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.contains('='));
    }

    #[tokio::test]
    async fn test_verify_challenge_success() {
        let mut mock_repo = MockChallengeRepo::new();
        let mut mock_crypto = MockCrypto::new();
        
        let challenge_bytes = vec![1u8; 32];
        let challenge_hash = vec![2u8; 32];
        let challenge = base64::encode_config(&challenge_bytes, base64::URL_SAFE_NO_PAD);
        
        let stored_challenge = Challenge::new(
            challenge_hash.clone(),
            Some(Uuid::new_v4()),
            ChallengeType::Registration,
            5,
        ).unwrap();
        
        mock_crypto
            .expect_hash_challenge()
            .returning(|_| Ok(challenge_hash));
        
        mock_repo
            .expect_get_challenge_by_hash()
            .returning(|_, _, _| Ok(Some(stored_challenge)));
        
        mock_repo
            .expect_mark_challenge_used()
            .returning(|_| Ok(()));
        
        let service = ChallengeService::new(
            Arc::new(mock_repo),
            Arc::new(mock_crypto),
        );
        
        let result = service.verify_challenge(&challenge, Some(Uuid::new_v4()), ChallengeType::Registration).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_challenge_not_found() {
        let mut mock_repo = MockChallengeRepo::new();
        let mut mock_crypto = MockCrypto::new();
        
        let challenge_bytes = vec![1u8; 32];
        let challenge_hash = vec![2u8; 32];
        let challenge = base64::encode_config(&challenge_bytes, base64::URL_SAFE_NO_PAD);
        
        mock_crypto
            .expect_hash_challenge()
            .returning(|_| Ok(challenge_hash));
        
        mock_repo
            .expect_get_challenge_by_hash()
            .returning(|_, _, _| Ok(None));
        
        let service = ChallengeService::new(
            Arc::new(mock_repo),
            Arc::new(mock_crypto),
        );
        
        let result = service.verify_challenge(&challenge, Some(Uuid::new_v4()), ChallengeType::Registration).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidChallenge));
    }

    #[tokio::test]
    async fn test_verify_challenge_invalid_encoding() {
        let mock_repo = MockChallengeRepo::new();
        let mock_crypto = MockCrypto::new();
        
        let service = ChallengeService::new(
            Arc::new(mock_repo),
            Arc::new(mock_crypto),
        );
        
        let invalid_challenge = "invalid!base64";
        let result = service.verify_challenge(invalid_challenge, None, ChallengeType::Registration).await;
        assert!(result.is_err());
    }
}