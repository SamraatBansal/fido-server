//! WebAuthn-specific models and types

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// User entity for WebAuthn operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Credential entity for WebAuthn operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: String,
    pub attestation_format: String,
    pub sign_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub transports: Option<Vec<String>>,
}

/// Challenge entity for WebAuthn operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: String,
    pub challenge_type: ChallengeType,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

/// Challenge type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Attestation,
    Assertion,
}

impl Challenge {
    pub fn new_attestation(user_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Some(user_id),
            challenge: generate_challenge(),
            challenge_type: ChallengeType::Attestation,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            used: false,
            created_at: Utc::now(),
        }
    }

    pub fn new_assertion(_username: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: None, // Will be resolved when user is found
            challenge: generate_challenge(),
            challenge_type: ChallengeType::Assertion,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            used: false,
            created_at: Utc::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Generate a secure random challenge
fn generate_challenge() -> String {
    use base64::{Engine as _, engine::general_purpose};
    use rand::RngCore;
    
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// WebAuthn configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u64,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
            timeout: 60000, // 60 seconds
        }
    }
}