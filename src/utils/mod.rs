//! Utility functions

use chrono::{DateTime, Utc, Duration};
use base64::Engine;

/// Generate a random challenge string
pub fn generate_challenge() -> String {
    let challenge_bytes = rand::random::<[u8; 32]>();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)
}

/// Check if a timestamp is expired
pub fn is_expired(timestamp: DateTime<Utc>) -> bool {
    timestamp < Utc::now()
}

/// Get default challenge expiration time (5 minutes from now)
pub fn default_challenge_expiration() -> DateTime<Utc> {
    Utc::now() + Duration::minutes(5)
}