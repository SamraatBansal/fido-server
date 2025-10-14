//! Cryptographic utilities

use crate::error::{AppError, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub trait CryptoService: Send + Sync {
    fn generate_secure_random(&self, length: usize) -> Result<Vec<u8>>;
    fn hash_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>>;
    fn verify_challenge_hash(&self, challenge: &[u8], hash: &[u8]) -> Result<bool>;
}

pub struct CryptoServiceImpl;

impl CryptoServiceImpl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl CryptoService for CryptoServiceImpl {
    fn generate_secure_random(&self, length: usize) -> Result<Vec<u8>> {
        if length == 0 || length > 1024 {
            return Err(AppError::InvalidInput(
                "Length must be between 1 and 1024 bytes".to_string(),
            ));
        }

        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut bytes);
        Ok(bytes)
    }

    fn hash_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        Ok(hasher.finalize().to_vec())
    }

    fn verify_challenge_hash(&self, challenge: &[u8], hash: &[u8]) -> Result<bool> {
        let computed_hash = self.hash_challenge(challenge)?;
        Ok(computed_hash == hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_generate_secure_random() {
        let crypto = CryptoServiceImpl::new();
        
        // Test valid lengths
        let bytes1 = crypto.generate_secure_random(32).unwrap();
        assert_eq!(bytes1.len(), 32);
        
        let bytes2 = crypto.generate_secure_random(32).unwrap();
        assert_eq!(bytes2.len(), 32);
        
        // Ensure randomness
        assert_ne!(bytes1, bytes2);
        
        // Test invalid lengths
        assert!(crypto.generate_secure_random(0).is_err());
        assert!(crypto.generate_secure_random(1025).is_err());
    }

    #[test]
    fn test_hash_challenge() {
        let crypto = CryptoServiceImpl::new();
        let challenge = b"test_challenge";
        
        let hash1 = crypto.hash_challenge(challenge).unwrap();
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
        
        let hash2 = crypto.hash_challenge(challenge).unwrap();
        assert_eq!(hash1, hash2); // Same input should produce same hash
        
        // Different input should produce different hash
        let hash3 = crypto.hash_challenge(b"different_challenge").unwrap();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_verify_challenge_hash() {
        let crypto = CryptoServiceImpl::new();
        let challenge = b"test_challenge";
        
        let hash = crypto.hash_challenge(challenge).unwrap();
        
        // Valid verification
        assert!(crypto.verify_challenge_hash(challenge, &hash).unwrap());
        
        // Invalid verification
        assert!(!crypto.verify_challenge_hash(b"wrong_challenge", &hash).unwrap());
        assert!(!crypto.verify_challenge_hash(challenge, b"wrong_hash").unwrap());
    }

    #[test]
    fn test_hash_deterministic() {
        let crypto = CryptoServiceImpl::new();
        let challenge = b"deterministic_test";
        
        let hash1 = crypto.hash_challenge(challenge).unwrap();
        let hash2 = crypto.hash_challenge(challenge).unwrap();
        let hash3 = crypto.hash_challenge(challenge).unwrap();
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn test_hash_different_lengths() {
        let crypto = CryptoServiceImpl::new();
        
        // Test various challenge lengths
        let challenges = vec![
            b"",
            b"a",
            b"short",
            b"medium_length_challenge",
            b"this_is_a_very_long_challenge_that_tests_the_hash_function_with_more_data".as_bytes(),
        ];
        
        for challenge in challenges {
            let hash = crypto.hash_challenge(challenge).unwrap();
            assert_eq!(hash.len(), 32);
            assert!(crypto.verify_challenge_hash(challenge, &hash).unwrap());
        }
    }
}