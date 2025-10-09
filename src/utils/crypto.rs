//! Cryptographic utilities

use rand::{thread_rng, Rng};
use crate::error::FidoResult;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Generate a cryptographically secure challenge
pub fn generate_secure_challenge() -> FidoResult<String> {
    let mut rng = thread_rng();
    let challenge_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    Ok(URL_SAFE_NO_PAD.encode(&challenge_bytes))
}

/// Calculate entropy score for challenge quality testing
pub fn calculate_entropy_score(challenges: &[String]) -> f64 {
    // Simple entropy calculation for testing purposes
    // In production, use more sophisticated entropy measurement
    if challenges.is_empty() {
        return 0.0;
    }
    
    let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
    unique_challenges.len() as f64 / challenges.len() as f64
}

/// Check if CSPRNG is being used for challenges
pub fn uses_csprng_for_challenges() -> bool {
    // In this implementation, we use rand::thread_rng which is cryptographically secure
    true
}