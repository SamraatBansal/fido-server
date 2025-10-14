//! Challenge store for WebAuthn operations

use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

pub struct ChallengeStore {
    challenges: HashMap<String, (String, DateTime<Utc>)>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    pub fn store_challenge(&mut self, challenge: String, challenge_type: String) {
        let expires_at = Utc::now() + Duration::minutes(5);
        self.challenges.insert(challenge, (challenge_type, expires_at));
    }

    pub fn validate_and_remove_challenge(&mut self, challenge: &str, expected_type: &str) -> Result<(), String> {
        if let Some((challenge_type, expires_at)) = self.challenges.remove(challenge) {
            if challenge_type != expected_type {
                return Err("Invalid challenge type!".to_string());
            }

            if Utc::now() > expires_at {
                return Err("Challenge has expired!".to_string());
            }

            Ok(())
        } else {
            Err("Invalid or expired challenge!".to_string())
        }
    }

    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.challenges.retain(|_, (_, expires_at)| *expires_at > now);
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

// Global challenge store instance
use std::sync::Mutex;
use once_cell::sync::Lazy;

static CHALLENGE_STORE: Lazy<Mutex<ChallengeStore>> = Lazy::new(|| {
    Mutex::new(ChallengeStore::new())
});

pub fn get_challenge_store() -> &'static Mutex<ChallengeStore> {
    &CHALLENGE_STORE
}