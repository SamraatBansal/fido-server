//! Secure session management for WebAuthn operations
//! 
//! This module provides secure session storage and challenge management
//! for registration and authentication flows.

use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::error::{AppError, Result};

/// Secure session data for WebAuthn operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    pub session_id: String,
    pub user_id: Uuid,
    pub challenge: String,
    pub operation_type: OperationType,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_data: Option<String>,
    pub user_verification: UserVerificationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    Registration,
    Authentication,
}

/// Trait for secure challenge storage
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Store challenge data securely
    async fn store_challenge(&self, session_id: &str, challenge: ChallengeData) -> Result<()>;
    
    /// Retrieve challenge data by session ID
    async fn get_challenge(&self, session_id: &str) -> Result<Option<ChallengeData>>;
    
    /// Delete challenge data
    async fn delete_challenge(&self, session_id: &str) -> Result<()>;
    
    /// Clean up expired challenges
    async fn cleanup_expired(&self) -> Result<usize>;
    
    /// Check if session exists and is valid
    async fn is_session_valid(&self, session_id: &str) -> Result<bool>;
}

/// Redis-based challenge store implementation
pub struct RedisChallengeStore {
    client: Arc<redis::Client>,
    session_timeout: Duration,
}

impl RedisChallengeStore {
    pub fn new(client: Arc<redis::Client>, session_timeout: Duration) -> Self {
        Self {
            client,
            session_timeout,
        }
    }

    fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .map_err(|e| AppError::DatabaseConnection(format!("Redis connection failed: {}", e)))
    }
}

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn store_challenge(&self, session_id: &str, challenge: ChallengeData) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let serialized = serde_json::to_string(&challenge)
            .map_err(AppError::Serialization)?;
        
        let key = format!("webauthn:challenge:{}", session_id);
        let ttl = self.session_timeout.as_secs() as usize;
        
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(&serialized)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseConnection(format!("Redis store failed: {}", e)))?;
        
        Ok(())
    }

    async fn get_challenge(&self, session_id: &str) -> Result<Option<ChallengeData>> {
        let mut conn = self.get_connection().await?;
        let key = format!("webauthn:challenge:{}", session_id);
        
        let serialized: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseConnection(format!("Redis get failed: {}", e)))?;
        
        match serialized {
            Some(data) => {
                let challenge: ChallengeData = serde_json::from_str(&data)
                    .map_err(AppError::Serialization)?;
                
                // Check if challenge has expired
                if challenge.expires_at < Utc::now() {
                    self.delete_challenge(session_id).await?;
                    return Ok(None);
                }
                
                Ok(Some(challenge))
            }
            None => Ok(None),
        }
    }

    async fn delete_challenge(&self, session_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let key = format!("webauthn:challenge:{}", session_id);
        
        redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::DatabaseConnection(format!("Redis delete failed: {}", e)))?;
        
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        // Redis automatically handles expiration with TTL
        // This is a no-op for Redis implementation
        Ok(0)
    }

    async fn is_session_valid(&self, session_id: &str) -> Result<bool> {
        let challenge = self.get_challenge(session_id).await?;
        Ok(challenge.is_some())
    }
}

/// In-memory challenge store for development/testing
pub struct MemoryChallengeStore {
    challenges: Arc<tokio::sync::RwLock<std::collections::HashMap<String, ChallengeData>>>,
    session_timeout: Duration,
}

impl MemoryChallengeStore {
    pub fn new(session_timeout: Duration) -> Self {
        Self {
            challenges: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            session_timeout,
        }
    }

    async fn cleanup_expired_internal(&self) -> usize {
        let mut challenges = self.challenges.write().await;
        let now = Utc::now();
        let initial_count = challenges.len();
        
        challenges.retain(|_, challenge| challenge.expires_at > now);
        
        initial_count - challenges.len()
    }
}

#[async_trait]
impl ChallengeStore for MemoryChallengeStore {
    async fn store_challenge(&self, session_id: &str, challenge: ChallengeData) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        challenges.insert(session_id.to_string(), challenge);
        Ok(())
    }

    async fn get_challenge(&self, session_id: &str) -> Result<Option<ChallengeData>> {
        let challenges = self.challenges.read().await;
        
        match challenges.get(session_id) {
            Some(challenge) => {
                if challenge.expires_at < Utc::now() {
                    drop(challenges);
                    self.delete_challenge(session_id).await?;
                    return Ok(None);
                }
                Ok(Some(challenge.clone()))
            }
            None => Ok(None),
        }
    }

    async fn delete_challenge(&self, session_id: &str) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        challenges.remove(session_id);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        Ok(self.cleanup_expired_internal().await)
    }

    async fn is_session_valid(&self, session_id: &str) -> Result<bool> {
        let challenges = self.challenges.read().await;
        
        match challenges.get(session_id) {
            Some(challenge) => Ok(challenge.expires_at > Utc::now()),
            None => Ok(false),
        }
    }
}

/// Secure session manager
pub struct SecureSessionManager {
    challenge_store: Arc<dyn ChallengeStore>,
    session_timeout: Duration,
    max_sessions_per_user: usize,
    encryption_key: [u8; 32],
}

impl SecureSessionManager {
    pub fn new(
        challenge_store: Arc<dyn ChallengeStore>,
        session_timeout: Duration,
        max_sessions_per_user: usize,
        encryption_key: [u8; 32],
    ) -> Self {
        Self {
            challenge_store,
            session_timeout,
            max_sessions_per_user,
            encryption_key,
        }
    }

    /// Generate a secure session ID
    pub fn generate_session_id(&self) -> Result<String> {
        let uuid = Uuid::new_v4();
        Ok(uuid.to_string())
    }

    /// Create a new challenge session
    pub async fn create_challenge_session(
        &self,
        user_id: Uuid,
        challenge: String,
        operation_type: OperationType,
        user_verification: UserVerificationPolicy,
        client_data: Option<String>,
    ) -> Result<String> {
        let session_id = self.generate_session_id()?;
        let now = Utc::now();
        
        let challenge_data = ChallengeData {
            session_id: session_id.clone(),
            user_id,
            challenge,
            operation_type,
            created_at: now,
            expires_at: now + self.session_timeout,
            client_data,
            user_verification,
        };

        self.challenge_store.store_challenge(&session_id, challenge_data).await?;
        Ok(session_id)
    }

    /// Validate and retrieve challenge session
    pub async fn validate_challenge_session(
        &self,
        session_id: &str,
        expected_operation: OperationType,
    ) -> Result<ChallengeData> {
        let challenge_data = self.challenge_store
            .get_challenge(session_id)
            .await?
            .ok_or(AppError::SessionNotFound)?;

        if challenge_data.operation_type != expected_operation {
            return Err(AppError::InvalidSessionState);
        }

        if challenge_data.expires_at < Utc::now() {
            self.challenge_store.delete_challenge(session_id).await?;
            return Err(AppError::SessionExpired);
        }

        Ok(challenge_data)
    }

    /// Delete a challenge session
    pub async fn delete_challenge_session(&self, session_id: &str) -> Result<()> {
        self.challenge_store.delete_challenge(session_id).await
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        self.challenge_store.cleanup_expired().await
    }

    /// Check if session is valid
    pub async fn is_session_valid(&self, session_id: &str) -> Result<bool> {
        self.challenge_store.is_session_valid(session_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_memory_challenge_store() {
        let store = MemoryChallengeStore::new(Duration::from_secs(60));
        let session_id = "test-session";
        
        let challenge_data = ChallengeData {
            session_id: session_id.to_string(),
            user_id: Uuid::new_v4(),
            challenge: "test-challenge".to_string(),
            operation_type: OperationType::Registration,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::from_secs(60),
            client_data: None,
            user_verification: UserVerificationPolicy::Preferred,
        };

        // Store challenge
        store.store_challenge(session_id, challenge_data.clone()).await.unwrap();
        
        // Retrieve challenge
        let retrieved = store.get_challenge(session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().challenge, "test-challenge");
        
        // Delete challenge
        store.delete_challenge(session_id).await.unwrap();
        
        // Verify deletion
        let deleted = store.get_challenge(session_id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_session_manager() {
        let store = Arc::new(MemoryChallengeStore::new(Duration::from_secs(60)));
        let session_manager = SecureSessionManager::new(
            store,
            Duration::from_secs(60),
            10,
            [0u8; 32],
        );

        let user_id = Uuid::new_v4();
        let session_id = session_manager
            .create_challenge_session(
                user_id,
                "test-challenge".to_string(),
                OperationType::Registration,
                UserVerificationPolicy::Preferred,
                None,
            )
            .await
            .unwrap();

        // Validate session
        let challenge_data = session_manager
            .validate_challenge_session(&session_id, OperationType::Registration)
            .await
            .unwrap();

        assert_eq!(challenge_data.user_id, user_id);
        assert_eq!(challenge_data.challenge, "test-challenge");

        // Delete session
        session_manager.delete_challenge_session(&session_id).await.unwrap();

        // Verify session is gone
        let is_valid = session_manager.is_session_valid(&session_id).await.unwrap();
        assert!(!is_valid);
    }
}