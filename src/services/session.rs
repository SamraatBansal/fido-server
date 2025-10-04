//! Session management service

use std::sync::Arc;
use uuid::Uuid;

use crate::db::models::{NewSession, Session};
use crate::db::repositories::SessionRepository;
use crate::error::{AppError, Result};

pub struct SessionService {
    session_repo: Arc<dyn SessionRepository>,
}

impl SessionService {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    /// Create a new session
    pub async fn create_session(
        &self,
        user_id: Option<Uuid>,
        challenge: String,
        session_type: &str,
        expires_in_minutes: i64,
    ) -> Result<Session> {
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(expires_in_minutes);
        
        let new_session = NewSession {
            user_id,
            challenge,
            session_type: session_type.to_string(),
            expires_at,
        };

        self.session_repo.create_session(&new_session).await
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &Uuid) -> Result<Option<Session>> {
        self.session_repo.find_by_id(session_id).await
    }

    /// Get session by challenge
    pub async fn get_session_by_challenge(&self, challenge: &str) -> Result<Option<Session>> {
        self.session_repo.find_by_challenge(challenge).await
    }

    /// Delete session
    pub async fn delete_session(&self, session_id: &Uuid) -> Result<()> {
        self.session_repo.delete_session(session_id).await
    }

    /// Validate session (check if exists and not expired)
    pub async fn validate_session(&self, session_id: &Uuid) -> Result<Option<Session>> {
        let session = self.session_repo.find_by_id(session_id).await?;
        
        if let Some(ref sess) = session {
            if sess.expires_at < chrono::Utc::now() {
                // Session expired, delete it
                self.session_repo.delete_session(session_id).await?;
                return Ok(None);
            }
        }
        
        Ok(session)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        self.session_repo.cleanup_expired_sessions().await
    }
}