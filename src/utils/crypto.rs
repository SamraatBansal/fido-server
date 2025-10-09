//! Cryptographic utilities for WebAuthn operations

use base64::{Engine as _, engine::general_purpose};
use rand::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a cryptographically secure random challenge
pub fn generate_secure_challenge() -> String {
    let mut challenge_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut challenge_bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)
}

/// Generate a random user ID
pub fn generate_user_id() -> String {
    let mut user_id_bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut user_id_bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(user_id_bytes)
}

/// Generate a random credential ID
pub fn generate_credential_id() -> String {
    let mut cred_id_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut cred_id_bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(cred_id_bytes)
}

/// Calculate SHA-256 hash of data
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Get current timestamp in milliseconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Validate base64url encoding and decode
pub fn decode_base64url(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(data)
}

/// Encode data as base64url
pub fn encode_base64url(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Verify cryptographic entropy of challenges
pub fn verify_entropy(challenges: &[String]) -> bool {
    if challenges.len() < 100 {
        return false;
    }
    
    // Convert all challenges to bytes
    let all_bytes: Vec<u8> = challenges
        .iter()
        .filter_map(|c| decode_base64url(c).ok())
        .flatten()
        .collect();
    
    if all_bytes.len() < 2560 {
        return false; // Need at least 2560 bytes for entropy test
    }
    
    // Simple entropy test: check byte distribution
    let mut byte_counts = [0u64; 256];
    for byte in &all_bytes {
        byte_counts[*byte as usize] += 1;
    }
    
    // Calculate Shannon entropy
    let total_bytes = all_bytes.len() as f64;
    let mut entropy = 0.0;
    
    for count in &byte_counts {
        if *count > 0 {
            let probability = *count as f64 / total_bytes;
            entropy -= probability * probability.log2();
        }
    }
    
    // Entropy should be close to 8.0 for good randomness
    entropy > 7.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_challenge() {
        let challenge1 = generate_secure_challenge();
        let challenge2 = generate_secure_challenge();
        
        assert_ne!(challenge1, challenge2, "Challenges should be unique");
        assert!(challenge1.len() >= 16, "Challenge should be at least 16 chars");
        assert!(challenge2.len() >= 16, "Challenge should be at least 16 chars");
        
        // Should be valid base64url
        assert!(decode_base64url(&challenge1).is_ok());
        assert!(decode_base64url(&challenge2).is_ok());
    }

    #[test]
    fn test_generate_user_id() {
        let user_id1 = generate_user_id();
        let user_id2 = generate_user_id();
        
        assert_ne!(user_id1, user_id2, "User IDs should be unique");
        assert!(user_id1.len() >= 16, "User ID should be at least 16 chars");
        
        // Should be valid base64url
        assert!(decode_base64url(&user_id1).is_ok());
    }

    #[test]
    fn test_generate_credential_id() {
        let cred_id1 = generate_credential_id();
        let cred_id2 = generate_credential_id();
        
        assert_ne!(cred_id1, cred_id2, "Credential IDs should be unique");
        assert!(cred_id1.len() >= 16, "Credential ID should be at least 16 chars");
        
        // Should be valid base64url
        assert!(decode_base64url(&cred_id1).is_ok());
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash1 = sha256_hash(data);
        let hash2 = sha256_hash(data);
        
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 should produce 32 bytes");
    }

    #[test]
    fn test_base64url_encoding() {
        let data = b"hello world";
        let encoded = encode_base64url(data);
        let decoded = decode_base64url(&encoded).unwrap();
        
        assert_eq!(decoded, data, "Encoding/decoding should be reversible");
    }

    #[test]
    fn test_verify_entropy() {
        // Generate many challenges and test entropy
        let challenges: Vec<String> = (0..1000).map(|_| generate_secure_challenge()).collect();
        assert!(verify_entropy(&challenges), "Generated challenges should have good entropy");
        
        // Test with insufficient data
        let few_challenges: Vec<String> = (0..10).map(|_| generate_secure_challenge()).collect();
        assert!(!verify_entropy(&few_challenges), "Should fail with insufficient data");
    }
}