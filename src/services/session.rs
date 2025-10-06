//! Secure session management for WebAuthn operations
//! 
//! This module provides secure session storage and challenge management
//! with proper expiration, rate limiting, and security controls.

use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ring::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;

use crate::db::repositories::SessionRepository;
use crate::error::{AppError, Result};

/// Operation type for WebAuthn sessions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationType {
    Registration,
    Authentication,
}

/// Challenge data stored in sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    pub user_id: Uuid,
    pub challenge: String,
    pub operation_type: OperationType,
    pub user_verification: webauthn_rs::prelude::UserVerificationPolicy,
    pub client_data: Option<String>, // Serialized state data
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Secure session manager with comprehensive security controls
pub struct SecureSessionManager {
    session_repo: Arc<dyn SessionRepository>,
    session_timeout: Duration,
    max_sessions_per_user: usize,
    rng: SystemRandom,
}

impl SecureSessionManager {
    /// Create a new secure session manager
    pub fn new(
        session_repo: Arc<dyn SessionRepository>,
        session_timeout: Duration,
        max_sessions_per_user: usize,
    ) -> Self {
        Self {
            session_repo,
            session_timeout,
            max_sessions_per_user,
            rng: SystemRandom::new(),
        }
    }

    /// Create a new challenge session
    pub async fn create_challenge_session(
        &self,
        user_id: Uuid,
        challenge: String,
        operation_type: OperationType,
        user_verification: webauthn_rs::prelude::UserVerificationPolicy,
        client_data: Option<String>,
    ) -> Result<String> {
        // Check session limits per user
        self.check_session_limits(&user_id).await?;

        // Generate secure session ID
        let session_id = self.generate_secure_session_id()?;

        // Calculate expiration
        let now = Utc::now();
        let expires_at = now + self.session_timeout;

        // Create challenge data
        let challenge_data = ChallengeData {
            user_id,
            challenge,
            operation_type,
            user_verification,
            client_data,
            created_at: now,
            expires_at,
        };

        // Store session
        self.session_repo
            .create_session(&session_id, &challenge_data)
            .await?;

        Ok(session_id)
    }

    /// Validate and retrieve challenge session
    pub async fn validate_challenge_session(
        &self,
        session_id: &str,
        expected_operation: OperationType,
    ) -> Result<ChallengeData> {
        // Retrieve session
        let session = self.session_repo
            .find_by_id(session_id)
            .await?
            .ok_or(AppError::InvalidSession("Session not found".to_string()))?;

        // Check expiration
        if session.expires_at < Utc::now() {
            self.session_repo.delete_session(session_id).await?;
            return Err(AppError::InvalidSession("Session expired".to_string()));
        }

        // Check operation type
        if session.operation_type != expected_operation {
            return Err(AppError::InvalidSession("Invalid operation type".to_string()));
        }

        Ok(session)
    }

    /// Delete a challenge session
    pub async fn delete_challenge_session(&self, session_id: &str) -> Result<()> {
        self.session_repo.delete_session(session_id).await?;
        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let now = Utc::now();
        self.session_repo.delete_expired_sessions(now).await
    }

    /// Check session limits per user
    async fn check_session_limits(&self, user_id: &Uuid) -> Result<()> {
        let active_sessions = self.session_repo
            .count_active_sessions(user_id, Utc::now())
            .await?;

        if active_sessions >= self.max_sessions_per_user {
            return Err(AppError::TooManySessions(
                format!("Maximum {} sessions per user exceeded", self.max_sessions_per_user)
            ));
        }

        Ok(())
    }

    /// Generate a cryptographically secure session ID
    fn generate_secure_session_id(&self) -> Result<String> {
        let mut bytes = [0u8; 32];
        self.rng
            .fill(&mut bytes)
            .map_err(|e| AppError::Internal(format!("Failed to generate session ID: {}", e)))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::Session;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Mock session repository for testing
    struct MockSessionRepository {
        sessions: Arc<Mutex<HashMap<String, Session>>>,
    }

    impl MockSessionRepository {
        fn new() -> Self {
            Self {
                sessions: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl SessionRepository for MockSessionRepository {
        async fn create_session(&self, session_id: &str, data: &ChallengeData) -> Result<()> {
            let mut sessions = self.sessions.lock().unwrap();
            let session = Session {
                id: session_id.to_string(),
                user_id: data.user_id,
                challenge: data.challenge.clone(),
                operation_type: serde_json::to_string(&data.operation_type).unwrap(),
                user_verification: serde_json::to_string(&data.user_verification).unwrap(),
                client_data: data.client_data.clone(),
                created_at: data.created_at,
                expires_at: data.expires_at,
            };
            sessions.insert(session_id.to_string(), session);
            Ok(())
        }

        async fn find_by_id(&self, session_id: &str) -> Result<Option<Session>> {
            let sessions = self.sessions.lock().unwrap();
            Ok(sessions.get(session_id).cloned())
        }

        async fn delete_session(&self, session_id: &str) -> Result<()> {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(session_id);
            Ok(())
        }

        async fn count_active_sessions(&self, user_id: &Uuid, now: DateTime<Utc>) -> Result<i64> {
            let sessions = self.sessions.lock().unwrap();
            let count = sessions
                .values()
                .filter(|s| s.user_id == *user_id && s.expires_at > now)
                .count() as i64;
            Ok(count)
        }

        async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<usize> {
            let mut sessions = self.sessions.lock().unwrap();
            let initial_count = sessions.len();
            sessions.retain(|_, s| s.expires_at > now);
            Ok(initial_count - sessions.len())
        }
    }

    #[tokio::test]
    async fn test_create_and_validate_session() {
        let mock_repo = Arc::new(MockSessionRepository::new());
        let session_manager = SecureSessionManager::new(
            mock_repo,
            Duration::from_secs(300),
            5,
        );

        let user_id = Uuid::new_v4();
        let challenge = "test-challenge".to_string();
        
        let session_id = session_manager
            .create_challenge_session(
                user_id,
                challenge.clone(),
                OperationType::Registration,
                webauthn_rs::prelude::UserVerificationPolicy::Preferred,
                None,
            )
            .await
            .unwrap();

        let challenge_data = session_manager
            .validate_challenge_session(&session_id, OperationType::Registration)
            .await
            .unwrap();

        assert_eq!(challenge_data.user_id, user_id);
        assert_eq!(challenge_data.challenge, challenge);
        assert_eq!(challenge_data.operation_type, OperationType::Registration);
    }

    #[tokio::test]
    async fn test_session_expiration() {
        let mock_repo = Arc::new(MockSessionRepository::new());
        let session_manager = SecureSessionManager::new(
            mock_repo,
            Duration::from_millis(1), // Very short timeout
            5,
        );

        let user_id = Uuid::new_v4();
        let challenge = "test-challenge".to_string();
        
        let session_id = session_manager
            .create_challenge_session(
                user_id,
                challenge,
                OperationType::Registration,
                webauthn_rs::prelude::UserVerificationPolicy::Preferred,
                None,
            )
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = session_manager
            .validate_challenge_session(&session_id, OperationType::Registration)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidSession(_)));
    }
}