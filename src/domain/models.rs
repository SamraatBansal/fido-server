//! Domain models for FIDO2/WebAuthn

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            display_name,
            created_at: now,
            updated_at: now,
        }
    }
}

/// WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Credential {
    pub fn new(
        user_id: String,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        sign_count: u32,
        attestation_format: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            credential_id,
            public_key,
            sign_count,
            attestation_format,
            aaguid: None,
            transports: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Challenge for registration or authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub user_id: Option<String>,
    pub challenge: String,
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Challenge {
    pub fn new(user_id: Option<String>, challenge: String, challenge_type: ChallengeType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            challenge,
            challenge_type,
            expires_at: now + chrono::Duration::minutes(5), // 5 minute expiry
            created_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Challenge type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

/// Authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSession {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub challenge: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl AuthenticationSession {
    pub fn new(user_id: String, credential_id: String, challenge: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            credential_id,
            challenge,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new("test@example.com".to_string(), "Test User".to_string());
        
        assert!(!user.id.is_empty());
        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(user.created_at <= Utc::now());
        assert!(user.updated_at <= Utc::now());
    }

    #[test]
    fn test_credential_creation() {
        let credential = Credential::new(
            "user-id".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            0,
            "packed".to_string(),
        );
        
        assert!(!credential.id.is_empty());
        assert_eq!(credential.user_id, "user-id");
        assert_eq!(credential.credential_id, vec![1, 2, 3]);
        assert_eq!(credential.public_key, vec![4, 5, 6]);
        assert_eq!(credential.sign_count, 0);
        assert_eq!(credential.attestation_format, "packed");
    }

    #[test]
    fn test_challenge_creation() {
        let challenge = Challenge::new(
            Some("user-id".to_string()),
            "test-challenge".to_string(),
            ChallengeType::Registration,
        );
        
        assert!(!challenge.id.is_empty());
        assert_eq!(challenge.user_id, Some("user-id".to_string()));
        assert_eq!(challenge.challenge, "test-challenge");
        assert!(matches!(challenge.challenge_type, ChallengeType::Registration));
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_challenge_expiry() {
        let mut challenge = Challenge::new(
            Some("user-id".to_string()),
            "test-challenge".to_string(),
            ChallengeType::Registration,
        );
        
        // Set expiry to past
        challenge.expires_at = Utc::now() - chrono::Duration::minutes(1);
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_authentication_session_creation() {
        let session = AuthenticationSession::new(
            "user-id".to_string(),
            "credential-id".to_string(),
            "test-challenge".to_string(),
        );
        
        assert!(!session.id.is_empty());
        assert_eq!(session.user_id, "user-id");
        assert_eq!(session.credential_id, "credential-id");
        assert_eq!(session.challenge, "test-challenge");
        assert!(!session.is_expired());
    }
}