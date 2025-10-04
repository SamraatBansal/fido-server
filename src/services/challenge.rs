//! Challenge management service

use crate::error::{AppError, Result};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use base64::{Engine as _, engine::general_purpose};

/// Challenge type
#[derive(Debug, Clone)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
        }
    }
}

/// Challenge data
#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub challenge_data: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

/// Challenge service
pub struct ChallengeService {
    // In-memory storage (in production, use database)
    challenges: std::collections::HashMap<Uuid, Challenge>,
}

impl ChallengeService {
    /// Create new challenge service
    pub fn new() -> Self {
        Self {
            challenges: std::collections::HashMap::new(),
        }
    }

    /// Generate new challenge
    pub fn generate_challenge(
        &mut self,
        user_id: Option<Uuid>,
        challenge_type: ChallengeType,
    ) -> Result<Challenge> {
        let challenge_data = generate_secure_random(32)?;
        let challenge_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::minutes(5); // 5 minutes
        
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge_id,
            challenge_data,
            user_id,
            challenge_type,
            expires_at,
            used: false,
            created_at: Utc::now(),
        };
        
        self.challenges.insert(challenge_id, challenge.clone());
        Ok(challenge)
    }

    /// Validate challenge
    pub fn validate_challenge(
        &mut self,
        challenge_id: Uuid,
        challenge_data: &[u8],
    ) -> Result<Challenge> {
        let challenge = self.challenges
            .get(&challenge_id)
            .ok_or_else(|| AppError::BadRequest("Invalid challenge".to_string()))?
            .clone();
            
        if challenge.used {
            return Err(AppError::BadRequest("Challenge already used".to_string()));
        }
        
        if challenge.expires_at < Utc::now() {
            return Err(AppError::BadRequest("Challenge expired".to_string()));
        }
        
        if challenge.challenge_data != challenge_data {
            return Err(AppError::BadRequest("Invalid challenge data".to_string()));
        }
        
        // Mark as used
        if let Some(ch) = self.challenges.get_mut(&challenge_id) {
            ch.used = true;
        }
        
        Ok(challenge)
    }
}

/// Generate secure random bytes
fn generate_secure_random(len: usize) -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}