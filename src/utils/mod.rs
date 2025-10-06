//! Utility functions

use base64::{Engine as _, engine::general_purpose};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes[..]);
    bytes
}

/// Generate random challenge
pub fn generate_challenge() -> String {
    let bytes = generate_random_bytes(32);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash challenge
pub fn hash_challenge(challenge: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

/// Validate origin
pub fn validate_origin(origin: &str, allowed_origins: &[String]) -> bool {
    allowed_origins.iter().any(|allowed| {
        allowed == "*" || allowed == origin
    })
}

/// Validate RP ID
pub fn validate_rp_id(rp_id: &str, origin: &str) -> bool {
    if let Ok(url) = url::Url::parse(origin) {
        let host = url.host_str().unwrap_or("");
        rp_id == host || host.ends_with(&format!(".{}", rp_id))
    } else {
        false
    }
}

/// Sanitize error messages to prevent information leakage
pub fn sanitize_error_message(error: &str, is_internal: bool) -> String {
    if is_internal {
        error.to_string()
    } else {
        // Return generic error message for external responses
        "An error occurred. Please try again.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        assert_ne!(challenge1, challenge2);
        assert!(!challenge1.is_empty());
        assert!(!challenge2.is_empty());
    }

    #[test]
    fn test_hash_challenge() {
        let challenge = "test_challenge";
        let hash1 = hash_challenge(challenge);
        let hash2 = hash_challenge(challenge);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, challenge);
    }

    #[test]
    fn test_validate_origin() {
        let allowed_origins = vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ];
        
        assert!(validate_origin("https://example.com", &allowed_origins));
        assert!(validate_origin("https://app.example.com", &allowed_origins));
        assert!(!validate_origin("https://evil.com", &allowed_origins));
    }

    #[test]
    fn test_validate_rp_id() {
        assert!(validate_rp_id("example.com", "https://example.com"));
        assert!(validate_rp_id("example.com", "https://app.example.com"));
        assert!(!validate_rp_id("example.com", "https://evil.com"));
    }
}