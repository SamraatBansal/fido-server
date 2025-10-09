//! Database models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// User model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Credential model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Challenge model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub challenge_data: String,
    pub challenge_type: String, // "registration" or "authentication"
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed: bool,
}

/// Authentication session model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuthenticationSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub challenge_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authenticated: bool,
}

impl User {
    /// Create new user
    pub fn new(username: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            display_name,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Credential {
    /// Create new credential
    pub fn new(user_id: Uuid, credential_id: String, public_key: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            public_key,
            sign_count: 0,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Challenge {
    /// Create new challenge
    pub fn new(
        user_id: Option<Uuid>,
        username: Option<String>,
        challenge_data: String,
        challenge_type: String,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            username,
            challenge_data,
            challenge_type,
            expires_at,
            created_at: now,
            consumed: false,
        }
    }

    /// Check if challenge is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if challenge is valid (not expired and not consumed)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.consumed
    }
}

impl AuthenticationSession {
    /// Create new authentication session
    pub fn new(
        user_id: Uuid,
        credential_id: String,
        challenge_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            challenge_id,
            created_at: now,
            expires_at,
            authenticated: false,
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is valid (not expired and not authenticated)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "test@example.com".to_string(),
            "Test User".to_string(),
        );
        
        assert!(!user.id.to_string().is_empty());
        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
    }

    #[test]
    fn test_credential_creation() {
        let user_id = Uuid::new_v4();
        let credential = Credential::new(
            user_id,
            "test_credential_id".to_string(),
            vec![1, 2, 3, 4],
        );
        
        assert!(!credential.id.to_string().is_empty());
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.credential_id, "test_credential_id");
        assert_eq!(credential.sign_count, 0);
    }

    #[test]
    fn test_challenge_creation() {
        let user_id = Some(Uuid::new_v4());
        let challenge = Challenge::new(
            user_id,
            Some("testuser".to_string()),
            "challenge_data".to_string(),
            "registration".to_string(),
            Utc::now() + chrono::Duration::minutes(5),
        );
        
        assert!(!challenge.id.to_string().is_empty());
        assert_eq!(challenge.user_id, user_id);
        assert_eq!(challenge.challenge_type, "registration");
        assert!(!challenge.consumed);
        assert!(!challenge.is_expired());
        assert!(challenge.is_valid());
    }

    #[test]
    fn test_expired_challenge() {
        let challenge = Challenge::new(
            None,
            None,
            "challenge_data".to_string(),
            "registration".to_string(),
            Utc::now() - chrono::Duration::minutes(1), // Expired
        );
        
        assert!(challenge.is_expired());
        assert!(!challenge.is_valid());
    }

    #[test]
    fn test_consumed_challenge() {
        let mut challenge = Challenge::new(
            None,
            None,
            "challenge_data".to_string(),
            "registration".to_string(),
            Utc::now() + chrono::Duration::minutes(5),
        );
        
        challenge.consumed = true;
        assert!(!challenge.is_expired());
        assert!(!challenge.is_valid());
    }
}