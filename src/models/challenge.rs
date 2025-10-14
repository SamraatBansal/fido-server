//! Challenge domain model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Registration => "registration",
            ChallengeType::Authentication => "authentication",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_hash: Vec<u8>,
    pub user_id: Option<Uuid>, // None for authentication challenges where user is not yet known
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_used: bool,
}

impl Challenge {
    pub fn new(
        challenge_hash: Vec<u8>,
        user_id: Option<Uuid>,
        challenge_type: ChallengeType,
        expires_in_minutes: i64,
    ) -> Result<Self, crate::error::AppError> {
        // Validate challenge hash length
        if challenge_hash.len() != 32 {
            return Err(crate::error::AppError::InvalidInput(
                "Challenge hash must be exactly 32 bytes".to_string(),
            ));
        }

        let now = Utc::now();
        Ok(Challenge {
            id: Uuid::new_v4(),
            challenge_hash,
            user_id,
            challenge_type,
            expires_at: now + chrono::Duration::minutes(expires_in_minutes),
            created_at: now,
            is_used: false,
        })
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn mark_used(&mut self) {
        self.is_used = true;
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_creation_valid() {
        let challenge_hash = vec![1u8; 32];
        let user_id = Some(Uuid::new_v4());
        let challenge_type = ChallengeType::Registration;

        let challenge = Challenge::new(challenge_hash.clone(), user_id, challenge_type, 5).unwrap();

        assert_eq!(challenge.challenge_hash, challenge_hash);
        assert_eq!(challenge.user_id, user_id);
        assert!(matches!(challenge.challenge_type, ChallengeType::Registration));
        assert!(!challenge.is_expired());
        assert!(!challenge.is_used);
        assert!(challenge.is_valid());
    }

    #[test]
    fn test_challenge_creation_invalid_hash_length() {
        let challenge_hash = vec![1u8; 31]; // Wrong length
        let user_id = Some(Uuid::new_v4());
        let challenge_type = ChallengeType::Registration;

        let result = Challenge::new(challenge_hash, user_id, challenge_type, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_expiration() {
        let challenge_hash = vec![1u8; 32];
        let user_id = Some(Uuid::new_v4());
        let challenge_type = ChallengeType::Registration;

        let challenge = Challenge::new(challenge_hash, user_id, challenge_type, -1).unwrap(); // Expired

        assert!(challenge.is_expired());
        assert!(!challenge.is_valid());
    }

    #[test]
    fn test_challenge_mark_used() {
        let challenge_hash = vec![1u8; 32];
        let user_id = Some(Uuid::new_v4());
        let challenge_type = ChallengeType::Registration;

        let mut challenge = Challenge::new(challenge_hash, user_id, challenge_type, 5).unwrap();

        assert!(!challenge.is_used);
        assert!(challenge.is_valid());

        challenge.mark_used();

        assert!(challenge.is_used);
        assert!(!challenge.is_valid());
    }

    #[test]
    fn test_challenge_type_as_str() {
        assert_eq!(ChallengeType::Registration.as_str(), "registration");
        assert_eq!(ChallengeType::Authentication.as_str(), "authentication");
    }

    #[test]
    fn test_challenge_without_user() {
        let challenge_hash = vec![1u8; 32];
        let challenge_type = ChallengeType::Authentication;

        let challenge = Challenge::new(challenge_hash, None, challenge_type, 5).unwrap();

        assert!(challenge.user_id.is_none());
        assert!(matches!(challenge.challenge_type, ChallengeType::Authentication));
    }
}