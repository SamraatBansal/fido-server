//! Challenge management service

use async_trait::async_trait;
use crate::error::{AppError, Result};
use crate::schema::challenge::Challenge;
use uuid::Uuid;

/// Challenge store trait for dependency injection
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Store a challenge
    async fn store_challenge(&self, challenge: &Challenge) -> Result<()>;
    
    /// Validate and consume a challenge
    async fn validate_and_consume(&self, challenge_id: &str, response_challenge: &[u8]) -> Result<bool>;
    
    /// Clean up expired challenges
    async fn cleanup_expired(&self) -> Result<()>;
    
    /// Get a challenge by ID
    async fn get_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>>;
    
    /// Delete a challenge
    async fn delete_challenge(&self, challenge_id: &str) -> Result<()>;
}

/// In-memory challenge store for testing and development
#[derive(Debug, Default)]
pub struct InMemoryChallengeStore {
    challenges: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Challenge>>>,
}

impl InMemoryChallengeStore {
    /// Create a new in-memory challenge store
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.id.clone(), challenge.clone());
        Ok(())
    }

    async fn validate_and_consume(&self, challenge_id: &str, response_challenge: &[u8]) -> Result<bool> {
        let mut challenges = self.challenges.write().await;
        
        if let Some(challenge) = challenges.remove(challenge_id) {
            // Check if challenge has expired
            if challenge.is_expired() {
                return Err(AppError::BadRequest("Challenge has expired".to_string()));
            }

            // Validate the challenge response
            Ok(challenge.validate_response(response_challenge))
        } else {
            Err(AppError::NotFound("Challenge not found".to_string()))
        }
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        let now = chrono::Utc::now();
        
        challenges.retain(|_, challenge| challenge.expires_at > now);
        Ok(())
    }

    async fn get_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>> {
        let challenges = self.challenges.read().await;
        Ok(challenges.get(challenge_id).cloned())
    }

    async fn delete_challenge(&self, challenge_id: &str) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        challenges.remove(challenge_id);
        Ok(())
    }
}

/// Challenge service
pub struct ChallengeService {
    store: InMemoryChallengeStore,
}

impl ChallengeService {
    /// Create a new challenge service
    pub fn new(store: InMemoryChallengeStore) -> Self {
        Self { store }
    }

    /// Create a registration challenge
    pub async fn create_registration_challenge(&self, user_id: Uuid) -> Result<Challenge> {
        let challenge_data = self.generate_secure_random(32)?;
        let challenge = Challenge::registration(challenge_data, user_id);
        
        self.store.store_challenge(&challenge).await?;
        Ok(challenge)
    }

    /// Create an authentication challenge
    pub async fn create_authentication_challenge(&self, user_id: Uuid) -> Result<Challenge> {
        let challenge_data = self.generate_secure_random(32)?;
        let challenge = Challenge::authentication(challenge_data, user_id);
        
        self.store.store_challenge(&challenge).await?;
        Ok(challenge)
    }

    /// Validate a challenge response
    pub async fn validate_challenge(&self, challenge_id: &str, response: &[u8]) -> Result<()> {
        let is_valid = self.store.validate_and_consume(challenge_id, response).await?;
        
        if !is_valid {
            return Err(AppError::BadRequest("Invalid challenge response".to_string()));
        }
        
        Ok(())
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<()> {
        self.store.cleanup_expired().await
    }

    /// Get a challenge by ID (for internal use)
    pub async fn get_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>> {
        self.store.get_challenge(challenge_id).await
    }

    /// Generate cryptographically secure random bytes
    fn generate_secure_random(&self, length: usize) -> Result<Vec<u8>> {
        use rand::RngCore;
        
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_challenge_store() {
        let store = InMemoryChallengeStore::new();
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(vec![1, 2, 3, 4], user_id);

        // Store challenge
        store.store_challenge(&challenge).await.unwrap();

        // Get challenge
        let retrieved = store.get_challenge(&challenge.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), challenge);

        // Validate and consume challenge
        let is_valid = store.validate_and_consume(&challenge.id, &[1, 2, 3, 4]).await.unwrap();
        assert!(is_valid);

        // Challenge should be gone
        let retrieved_again = store.get_challenge(&challenge.id).await.unwrap();
        assert!(retrieved_again.is_none());
    }

    #[tokio::test]
    async fn test_challenge_validation_invalid_response() {
        let store = InMemoryChallengeStore::new();
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(vec![1, 2, 3, 4], user_id);

        store.store_challenge(&challenge).await.unwrap();

        // Try invalid response
        let result = store.validate_and_consume(&challenge.id, &[5, 6, 7, 8]).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_challenge_validation_not_found() {
        let store = InMemoryChallengeStore::new();

        // Try to validate non-existent challenge
        let result = store.validate_and_consume("non-existent", &[1, 2, 3, 4]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_challenge_service_registration() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = Uuid::new_v4();

        let challenge = service.create_registration_challenge(user_id).await.unwrap();
        
        assert_eq!(challenge.user_id, Some(user_id));
        assert!(matches!(challenge.challenge_type, crate::schema::challenge::ChallengeType::Registration));
        assert!(!challenge.is_expired());
    }

    #[tokio::test]
    async fn test_challenge_service_authentication() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = Uuid::new_v4();

        let challenge = service.create_authentication_challenge(user_id).await.unwrap();
        
        assert_eq!(challenge.user_id, Some(user_id));
        assert!(matches!(challenge.challenge_type, crate::schema::challenge::ChallengeType::Authentication));
        assert!(!challenge.is_expired());
    }

    #[tokio::test]
    async fn test_challenge_service_validate_success() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = Uuid::new_v4();

        let challenge = service.create_registration_challenge(user_id).await.unwrap();
        
        // Validate with correct response
        let result = service.validate_challenge(&challenge.id, &challenge.challenge_data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_challenge_service_validate_invalid() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = Uuid::new_v4();

        let challenge = service.create_registration_challenge(user_id).await.unwrap();
        
        // Validate with incorrect response
        let result = service.validate_challenge(&challenge.id, &[9, 9, 9, 9]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_cleanup_expired_challenges() {
        let store = InMemoryChallengeStore::new();
        let service = ChallengeService::new(store);
        let user_id = Uuid::new_v4();

        // Create a challenge that expires immediately
        let challenge_data = vec![1, 2, 3, 4];
        let mut expired_challenge = crate::schema::challenge::Challenge::registration(challenge_data, user_id);
        expired_challenge.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);

        // Store both challenges
        service.store.store_challenge(&expired_challenge).await.unwrap();
        let valid_challenge = service.create_registration_challenge(user_id).await.unwrap();

        // Cleanup expired challenges
        service.cleanup_expired_challenges().await.unwrap();

        // Valid challenge should still exist
        let retrieved = service.store.get_challenge(&valid_challenge.id).await.unwrap();
        assert!(retrieved.is_some());

        // Expired challenge should be gone
        let retrieved_expired = service.store.get_challenge(&expired_challenge.id).await.unwrap();
        assert!(retrieved_expired.is_none());
    }
}