//! Cryptographic utilities

use base64::Engine;
use rand::{thread_rng, Rng};

/// Generate a cryptographically random challenge
pub fn generate_challenge() -> String {
    let mut rng = thread_rng();
    let challenge: [u8; 32] = rng.gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
}

/// Generate a random user ID
pub fn generate_user_id() -> String {
    let mut rng = thread_rng();
    let user_id: [u8; 16] = rng.gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id)
}

/// Generate a random credential ID
pub fn generate_credential_id() -> String {
    let mut rng = thread_rng();
    let credential_id: [u8; 16] = rng.gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id)
}

/// Constant-time comparison to prevent timing attacks
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}