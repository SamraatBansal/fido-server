//! Cryptographic utilities

use rand::{thread_rng, RngCore};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::{Engine as _, engine::general_purpose};

type HmacSha256 = Hmac<Sha256>;

/// Generate cryptographically secure random bytes
pub fn generate_secure_random(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a random challenge for WebAuthn
pub fn generate_challenge() -> Vec<u8> {
    generate_secure_random(32)
}

/// Hash data using SHA-256
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    mac.update(data);
    Ok(mac.verify(signature).is_ok())
}

/// Encode bytes to base64url (URL-safe, no padding)
pub fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url string to bytes
pub fn base64url_decode(data: &str) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE_NO_PAD.decode(data)
        .map_err(|e| format!("Invalid base64url encoding: {}", e))
}

/// Encode bytes to base64 (standard, with padding)
pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode base64 string to bytes
pub fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD.decode(data)
        .map_err(|e| format!("Invalid base64 encoding: {}", e))
}

/// Generate a secure random string
pub fn generate_random_string(length: usize) -> String {
    let bytes = generate_secure_random(length);
    base64url_encode(&bytes)
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

/// Derive a key from a password using PBKDF2 (simplified version)
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    
    let mut key = vec![0u8; key_length];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    key
}

/// Generate a secure session token
pub fn generate_session_token() -> String {
    generate_random_string(32)
}

/// Generate a CSRF token
pub fn generate_csrf_token() -> String {
    generate_random_string(32)
}

/// Encrypt data using AES-GCM (placeholder implementation)
pub fn encrypt_aes_gcm(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    // In a real implementation, you would use a proper AES-GCM implementation
    // This is just a placeholder
    Err("AES-GCM encryption not implemented".to_string())
}

/// Decrypt data using AES-GCM (placeholder implementation)
pub fn decrypt_aes_gcm(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    // In a real implementation, you would use a proper AES-GCM implementation
    // This is just a placeholder
    Err("AES-GCM decryption not implemented".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_random() {
        let bytes1 = generate_secure_random(32);
        let bytes2 = generate_secure_random(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256_hash(data);
        
        // Known SHA-256 hash of "hello world"
        let expected = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"hello world";
        
        let signature = hmac_sha256(key, data).unwrap();
        let is_valid = verify_hmac_sha256(key, data, &signature).unwrap();
        
        assert!(is_valid);
        
        // Test with wrong data
        let is_invalid = verify_hmac_sha256(key, b"wrong data", &signature).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_base64url_encode_decode() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        
        assert_eq!(data, &decoded[..]);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        
        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"hello!")); // Different length
    }

    #[test]
    fn test_generate_random_string() {
        let s1 = generate_random_string(32);
        let s2 = generate_random_string(32);
        
        assert_eq!(s1.len(), 32);
        assert_eq!(s2.len(), 32);
        assert_ne!(s1, s2);
    }
}