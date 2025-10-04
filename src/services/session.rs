//! Session management service

use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use crate::db::{PooledDb, SessionRepository, NewSession, Session};
use crate::error::{AppError, Result};

/// Session service for managing user sessions
pub struct SessionService {
    jwt_secret: String,
    session_timeout_hours: i64,
}

impl SessionService {
    /// Create a new session service
    pub fn new(jwt_secret: String, session_timeout_hours: i64) -> Self {
        Self {
            jwt_secret,
            session_timeout_hours,
        }
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        let expires_at = Utc::now() + Duration::hours(self.session_timeout_hours);
        let session_token = self.generate_jwt_token(user_id, expires_at)?;
        
        let new_session = NewSession {
            user_id,
            session_token: session_token.clone(),
            expires_at,
            ip_address,
            user_agent,
        };

        SessionRepository::create(conn, new_session)?;
        
        Ok(session_token)
    }

    /// Validate a session token
    pub async fn validate_session(
        &self,
        conn: &mut PooledDb,
        session_token: &str,
    ) -> Result<Option<Session>> {
        // First validate JWT token
        let claims = self.decode_jwt_token(session_token)?;
        
        // Check if session exists in database and is not expired
        if let Some(session) = SessionRepository::find_by_token(conn, session_token)? {
            // Update last accessed time
            SessionRepository::update_accessed(conn, session.id)?;
            
            // Verify user ID matches
            if session.user_id == claims.user_id {
                Ok(Some(session))
            } else {
                Err(AppError::BadRequest("Session token user mismatch".to_string()))
            }
        } else {
            Ok(None)
        }
    }

    /// Invalidate a session (logout)
    pub async fn invalidate_session(
        &self,
        conn: &mut PooledDb,
        session_token: &str,
    ) -> Result<()> {
        if let Some(session) = SessionRepository::find_by_token(conn, session_token)? {
            SessionRepository::delete(conn, session.id)?;
            Ok(())
        } else {
            Err(AppError::NotFound("Session not found".to_string()))
        }
    }

    /// Invalidate all sessions for a user
    pub async fn invalidate_user_sessions(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
    ) -> Result<usize> {
        // This would need to be implemented in the repository
        // For now, return placeholder
        log::info!("Invalidating all sessions for user: {}", user_id);
        Ok(0)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self, conn: &mut PooledDb) -> Result<usize> {
        SessionRepository::cleanup_expired(conn)
    }

    /// Generate JWT token
    fn generate_jwt_token(&self, user_id: Uuid, expires_at: DateTime<Utc>) -> Result<String> {
        let claims = JwtClaims {
            sub: user_id.to_string(),
            user_id,
            exp: expires_at.timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
            iss: "fido-server".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        ).map_err(|e| AppError::InternalError(format!("Failed to generate JWT token: {}", e)))
    }

    /// Decode JWT token
    fn decode_jwt_token(&self, token: &str) -> Result<JwtClaims> {
        let token_data = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        ).map_err(|e| AppError::BadRequest(format!("Invalid session token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Get session timeout duration
    pub fn session_timeout(&self) -> Duration {
        Duration::hours(self.session_timeout_hours)
    }
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    user_id: Uuid,
    exp: usize,
    iat: usize,
    iss: String,
}

impl Default for SessionService {
    fn default() -> Self {
        Self::new(
            "default-secret-change-in-production".to_string(),
            24, // 24 hours default timeout
        )
    }
}