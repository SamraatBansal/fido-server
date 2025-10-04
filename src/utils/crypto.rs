//! Cryptographic utilities

use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

/// Generate a random challenge for WebAuthn
pub fn generate_challenge() -> String {
    let mut rng = thread_rng();
    let bytes: [u8; 32] = rng.gen();
    base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD)
}

/// Generate a random session ID
pub fn generate_session_id() -> String {
    let mut rng = thread_rng();
    let bytes: [u8; 16] = rng.gen();
    base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD)
}

/// Hash data using SHA-256
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    base64::encode_config(&result, base64::URL_SAFE_NO_PAD)
}

/// Verify SHA-256 hash
pub fn verify_sha256_hash(data: &[u8], hash: &str) -> bool {
    let computed_hash = sha256_hash(data);
    computed_hash == hash
}

/// Generate a secure random string
pub fn generate_secure_random(length: usize) -> String {
    let mut rng = thread_rng();
    let bytes: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
    base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        assert_ne!(challenge1, challenge2);
        assert!(challenge1.len() > 0);
        assert!(challenge2.len() > 0);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = sha256_hash(data);
        
        assert!(hash.len() > 0);
        assert_eq!(hash.len(), 43); // base64 URL-safe no pad for 32 bytes
    }

    #[test]
    fn test_verify_sha256_hash() {
        let data = b"test data";
        let hash = sha256_hash(data);
        
        assert!(verify_sha256_hash(data, &hash));
        assert!(!verify_sha256_hash(b"different data", &hash));
    }
}