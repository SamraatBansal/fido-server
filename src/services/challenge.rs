//! Challenge management service

use uuid::Uuid;
use std::time::Duration;
use chrono::{DateTime, Utc};
use rand::{thread_rng, RngCore};
use base64::{Engine as _, engine::general_purpose};
use crate::db::{PooledDb, ChallengeRepository, NewChallenge};
use crate::error::{AppError, Result};

/// Challenge service for managing WebAuthn challenges
pub struct ChallengeService {
    _db: std::marker::PhantomData<()>, // Placeholder for database connection
}

impl ChallengeService {
    /// Create a new challenge service
    pub fn new() -> Self {
        Self {
            _db: std::marker::PhantomData,
        }
    }

    /// Generate a new challenge
    pub async fn generate_challenge(
        &self,
        conn: &mut PooledDb,
        user_id: Option<Uuid>,
        challenge_type: &str,
        timeout_seconds: u64,
    ) -> Result<Challenge> {
        let challenge_data = self.generate_secure_random(32);
        let challenge_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::from_secs(timeout_seconds);
        
        let new_challenge = NewChallenge {
            challenge_id,
            challenge_data: general_purpose::URL_SAFE_NO_PAD.encode(&challenge_data),
            user_id,
            challenge_type: challenge_type.to_string(),
            expires_at,
            metadata: None,
        };
        
        let stored_challenge = ChallengeRepository::create(conn, new_challenge)?;
        
        Ok(Challenge {
            id: stored_challenge.id,
            challenge_id: stored_challenge.challenge_id,
            challenge_data: stored_challenge.challenge_data,
            user_id: stored_challenge.user_id,
            challenge_type: stored_challenge.challenge_type,
            expires_at: stored_challenge.expires_at,
            used: stored_challenge.used,
            created_at: stored_challenge.created_at,
            metadata: stored_challenge.metadata,
        })
    }
    
    /// Validate a challenge
    pub async fn validate_challenge(
        &self,
        conn: &mut PooledDb,
        challenge_id: Uuid,
        challenge_data: &[u8],
    ) -> Result<Challenge> {
        let stored_challenge = ChallengeRepository::find_by_challenge_id(conn, challenge_id)?
            .ok_or(AppError::WebAuthnError("Challenge not found".to_string()))?;
            
        if stored_challenge.used {
            return Err(AppError::WebAuthnError("Challenge already used".to_string()));
        }
        
        if stored_challenge.expires_at < Utc::now() {
            return Err(AppError::WebAuthnError("Challenge expired".to_string()));
        }
        
        // Decode stored challenge data and compare
        let stored_data = general_purpose::URL_SAFE_NO_PAD
            .decode(&stored_challenge.challenge_data)
            .map_err(|e| AppError::WebAuthnError(format!("Invalid challenge encoding: {}", e)))?;
        
        if stored_data != challenge_data {
            return Err(AppError::WebAuthnError("Challenge mismatch".to_string()));
        }
        
        // Mark as used
        ChallengeRepository::mark_used(conn, challenge_id)?;
        
        Ok(Challenge {
            id: stored_challenge.id,
            challenge_id: stored_challenge.challenge_id,
            challenge_data: stored_challenge.challenge_data,
            user_id: stored_challenge.user_id,
            challenge_type: stored_challenge.challenge_type,
            expires_at: stored_challenge.expires_at,
            used: true,
            created_at: stored_challenge.created_at,
            metadata: stored_challenge.metadata,
        })
    }
    
    /// Clean up expired challenges
    pub async fn cleanup_expired(&self, conn: &mut PooledDb) -> Result<usize> {
        ChallengeRepository::cleanup_expired(conn)
    }
    
    /// Generate cryptographically secure random bytes
    fn generate_secure_random(&self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}

/// Challenge representation
#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub challenge_data: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

impl Default for ChallengeService {
    fn default() -> Self {
        Self::new()
    }
}