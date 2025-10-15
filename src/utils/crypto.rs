//! Cryptographic Utilities
//! 
//! Secure cryptographic operations for FIDO2/WebAuthn server

use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate cryptographically secure random bytes
pub fn generate_secure_random(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a secure random challenge (32 bytes)
pub fn generate_challenge() -> Vec<u8> {
    generate_secure_random(32)
}

/// Generate a secure random session token
pub fn generate_session_token() -> String {
    let bytes = generate_secure_random(32);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute SHA-256 hash of data
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Secure string that zeros memory on drop
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create new secure string from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create new secure string from string
    pub fn from_string(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    /// Get reference to data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zero out memory when dropping
        for byte in &mut self.data {
            *byte = 0;
        }
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self::new(self.data.clone())
    }
}

/// Get current timestamp in milliseconds since Unix epoch
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Validate base64url encoding
pub fn is_valid_base64url(input: &str) -> bool {
    general_purpose::URL_SAFE_NO_PAD.decode(input).is_ok()
}

/// Safe base64url encoding with padding removal
pub fn encode_base64url(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Safe base64url decoding
pub fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(input)
}

/// Cryptographic security validator
pub struct CryptoValidator {
    min_challenge_length: usize,
    max_challenge_length: usize,
    allowed_algorithms: Vec<String>,
}

impl CryptoValidator {
    /// Create new crypto validator with secure defaults
    pub fn new() -> Self {
        Self {
            min_challenge_length: 16,
            max_challenge_length: 64,
            allowed_algorithms: vec![
                "ES256".to_string(),
                "RS256".to_string(),
                "EdDSA".to_string(),
            ],
        }
    }

    /// Validate challenge length and randomness
    pub fn validate_challenge(&self, challenge: &[u8]) -> Result<(), String> {
        if challenge.len() < self.min_challenge_length {
            return Err(format!(
                "Challenge too short: minimum {} bytes",
                self.min_challenge_length
            ));
        }

        if challenge.len() > self.max_challenge_length {
            return Err(format!(
                "Challenge too long: maximum {} bytes",
                self.max_challenge_length
            ));
        }

        // Basic randomness check - ensure not all zeros or all same byte
        let first_byte = challenge[0];
        let all_same = challenge.iter().all(|&b| b == first_byte);
        if all_same {
            return Err("Challenge appears to be non-random".to_string());
        }

        Ok(())
    }

    /// Validate algorithm support
    pub fn validate_algorithm(&self, algorithm: &str) -> Result<(), String> {
        if self.allowed_algorithms.contains(&algorithm.to_string()) {
            Ok(())
        } else {
            Err(format!(
                "Algorithm '{}' not supported. Allowed: {:?}",
                algorithm, self.allowed_algorithms
            ))
        }
    }

    /// Validate public key format and size
    pub fn validate_public_key(&self, public_key: &[u8], algorithm: &str) -> Result<(), String> {
        if public_key.is_empty() {
            return Err("Public key cannot be empty".to_string());
        }

        // Basic size validation based on algorithm
        match algorithm {
            "ES256" => {
                if public_key.len() < 32 {
                    return Err("ES256 public key too short".to_string());
                }
            }
            "RS256" => {
                if public_key.len() < 256 {
                    return Err("RS256 public key too short (minimum 2048 bits)".to_string());
                }
            }
            "EdDSA" => {
                if public_key.len() != 32 {
                    return Err("EdDSA public key must be exactly 32 bytes".to_string());
                }
            }
            _ => {
                return Err(format!("Unknown algorithm: {}", algorithm));
            }
        }

        Ok(())
    }

    /// Validate signature format
    pub fn validate_signature(&self, signature: &[u8], algorithm: &str) -> Result<(), String> {
        if signature.is_empty() {
            return Err("Signature cannot be empty".to_string());
        }

        // Basic size validation based on algorithm
        match algorithm {
            "ES256" => {
                // ECDSA signatures are typically 64 bytes (32 bytes for r, 32 for s)
                if signature.len() < 64 {
                    return Err("ES256 signature too short".to_string());
                }
            }
            "RS256" => {
                // RSA signatures vary in size but should be reasonable
                if signature.len() < 256 {
                    return Err("RS256 signature too short".to_string());
                }
            }
            "EdDSA" => {
                // Ed25519 signatures are exactly 64 bytes
                if signature.len() != 64 {
                    return Err("EdDSA signature must be exactly 64 bytes".to_string());
                }
            }
            _ => {
                return Err(format!("Unknown algorithm: {}", algorithm));
            }
        }

        Ok(())
    }
}

impl Default for CryptoValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_generation() {
        let bytes1 = generate_secure_random(32);
        let bytes2 = generate_secure_random(32);

        // Should be different
        assert_ne!(bytes1, bytes2);

        // Should be correct length
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);

        // Should not be all zeros
        assert!(!bytes1.iter().all(|&b| b == 0));
        assert!(!bytes2.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_challenge_generation() {
        let challenge = generate_challenge();
        assert_eq!(challenge.len(), 32);
        
        // Multiple challenges should be unique
        let challenge2 = generate_challenge();
        assert_ne!(challenge, challenge2);
    }

    #[test]
    fn test_session_token_generation() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();

        // Should be different
        assert_ne!(token1, token2);

        // Should be valid base64url
        assert!(is_valid_base64url(&token1));
        assert!(is_valid_base64url(&token2));

        // Should be reasonable length (32 bytes = 43 chars in base64url)
        assert_eq!(token1.len(), 43);
        assert_eq!(token2.len(), 43);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = sha256_hash(data);
        
        // SHA256 produces 32 bytes
        assert_eq!(hash.len(), 32);
        
        // Same input should produce same hash
        let hash2 = sha256_hash(data);
        assert_eq!(hash, hash2);
        
        // Different input should produce different hash
        let hash3 = sha256_hash(b"different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"test data";
        let b = b"test data";
        let c = b"different data";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, &b[..5])); // Different length
    }

    #[test]
    fn test_secure_string() {
        let data = b"secret data".to_vec();
        let secure_str = SecureString::new(data.clone());
        
        assert_eq!(secure_str.as_bytes(), &data);
        assert_eq!(secure_str.len(), data.len());
        assert!(!secure_str.is_empty());

        // Test cloning
        let cloned = secure_str.clone();
        assert_eq!(secure_str.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn test_base64url_encoding() {
        let data = b"test data";
        let encoded = encode_base64url(data);
        let decoded = decode_base64url(&encoded).unwrap();
        
        assert_eq!(data, &decoded[..]);
        assert!(is_valid_base64url(&encoded));
    }

    #[test]
    fn test_crypto_validator() {
        let validator = CryptoValidator::new();

        // Test challenge validation
        let valid_challenge = generate_challenge();
        assert!(validator.validate_challenge(&valid_challenge).is_ok());

        let short_challenge = vec![0; 8];
        assert!(validator.validate_challenge(&short_challenge).is_err());

        let long_challenge = vec![0; 100];
        assert!(validator.validate_challenge(&long_challenge).is_err());

        // Test algorithm validation
        assert!(validator.validate_algorithm("ES256").is_ok());
        assert!(validator.validate_algorithm("RS256").is_ok());
        assert!(validator.validate_algorithm("INVALID").is_err());

        // Test public key validation
        let es256_key = vec![0; 32];
        assert!(validator.validate_public_key(&es256_key, "ES256").is_ok());

        let short_key = vec![0; 16];
        assert!(validator.validate_public_key(&short_key, "ES256").is_err());

        // Test signature validation
        let es256_sig = vec![0; 64];
        assert!(validator.validate_signature(&es256_sig, "ES256").is_ok());

        let ed25519_sig = vec![0; 64];
        assert!(validator.validate_signature(&ed25519_sig, "EdDSA").is_ok());

        let wrong_ed_sig = vec![0; 32];
        assert!(validator.validate_signature(&wrong_ed_sig, "EdDSA").is_err());
    }

    #[test]
    fn test_timestamp() {
        let ts1 = current_timestamp_ms();
        let ts2 = current_timestamp_ms();
        
        // Should be reasonably close
        assert!(ts2 >= ts1);
        assert!(ts2 - ts1 < 1000); // Less than 1 second difference
    }
}