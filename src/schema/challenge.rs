//! Challenge schema definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Challenge type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChallengeType {
    /// Registration challenge
    Registration,
    /// Authentication challenge
    Authentication,
}

/// Challenge for WebAuthn operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Challenge {
    /// Unique challenge identifier
    pub id: String,
    /// Challenge data (base64url encoded)
    pub challenge_data: Vec<u8>,
    /// User ID this challenge is for (optional)
    pub user_id: Option<Uuid>,
    /// Type of challenge
    pub challenge_type: ChallengeType,
    /// When the challenge was created
    pub created_at: DateTime<Utc>,
    /// When the challenge expires
    pub expires_at: DateTime<Utc>,
}

impl Challenge {
    /// Create a new challenge
    pub fn new(
        challenge_data: Vec<u8>,
        challenge_type: ChallengeType,
        user_id: Option<Uuid>,
        ttl_minutes: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            challenge_data,
            user_id,
            challenge_type,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(ttl_minutes),
        }
    }

    /// Create a registration challenge
    pub fn registration(challenge_data: Vec<u8>, user_id: Uuid) -> Self {
        Self::new(challenge_data, ChallengeType::Registration, Some(user_id), 5)
    }

    /// Create an authentication challenge
    pub fn authentication(challenge_data: Vec<u8>, user_id: Uuid) -> Self {
        Self::new(challenge_data, ChallengeType::Authentication, Some(user_id), 5)
    }

    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Validate challenge response
    pub fn validate_response(&self, response_challenge: &[u8]) -> bool {
        // Constant-time comparison to prevent timing attacks
        if self.challenge_data.len() != response_challenge.len() {
            return false;
        }

        // Simple byte-by-byte comparison (in production, use constant-time compare)
        self.challenge_data
            .iter()
            .zip(response_challenge.iter())
            .all(|(a, b)| a == b)
    }

    /// Get remaining time until expiration
    pub fn time_until_expiration(&self) -> chrono::Duration {
        self.expires_at.signed_duration_since(Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_creation() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(challenge_data.clone(), user_id);

        assert_eq!(challenge.challenge_data, challenge_data);
        assert_eq!(challenge.user_id, Some(user_id));
        assert!(matches!(challenge.challenge_type, ChallengeType::Registration));
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_challenge_authentication() {
        let challenge_data = vec![5, 6, 7, 8];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::authentication(challenge_data.clone(), user_id);

        assert_eq!(challenge.challenge_data, challenge_data);
        assert_eq!(challenge.user_id, Some(user_id));
        assert!(matches!(challenge.challenge_type, ChallengeType::Authentication));
    }

    #[test]
    fn test_challenge_expiration() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        
        // Create a challenge that expires immediately
        let challenge = Challenge::new(
            challenge_data,
            ChallengeType::Registration,
            Some(user_id),
            0, // 0 minutes TTL
        );

        // Should be expired
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_challenge_validation_success() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(challenge_data.clone(), user_id);

        // Valid response should match
        assert!(challenge.validate_response(&challenge_data));
    }

    #[test]
    fn test_challenge_validation_invalid_response() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(challenge_data, user_id);

        // Invalid response should not match
        assert!(!challenge.validate_response(&[5, 6, 7, 8]));
    }

    #[test]
    fn test_challenge_validation_wrong_length() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(challenge_data, user_id);

        // Wrong length should not match
        assert!(!challenge.validate_response(&[1, 2, 3]));
    }

    #[test]
    fn test_time_until_expiration() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(challenge_data, user_id);

        // Should have positive time remaining
        let time_remaining = challenge.time_until_expiration();
        assert!(time_remaining.num_minutes() > 0);
        assert!(time_remaining.num_minutes() <= 5); // Should be close to 5 minutes
    }

    #[test]
    fn test_challenge_serialization() {
        let challenge_data = vec![1, 2, 3, 4];
        let user_id = Uuid::new_v4();
        let challenge = Challenge::registration(challenge_data, user_id);

        // Test serialization/deserialization
        let serialized = serde_json::to_string(&challenge).unwrap();
        let deserialized: Challenge = serde_json::from_str(&serialized).unwrap();

        assert_eq!(challenge, deserialized);
    }
}