//! Cryptographic security tests

#[cfg(test)]
mod tests {
    use crate::common::*;
    use fido2_webauthn_server::utils::crypto::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_challenge_entropy() {
        // Generate multiple challenges and test entropy
        let challenges: Vec<String> = (0..1000).map(|_| fido2_webauthn_server::utils::crypto::generate_secure_challenge().unwrap()).collect();
        
        // Test uniqueness
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), challenges.len());
        
        // Test minimum length
        for challenge in &challenges {
            assert!(challenge.len() >= 16);
        }
        
        // Test base64url encoding
        for challenge in &challenges {
            assert!(base64::decode_config(challenge, base64::URL_SAFE_NO_PAD).is_ok());
        }
    }

    #[test]
    fn test_entropy_quality() {
        // Test entropy quality with statistical analysis
        let challenges: Vec<String> = (0..1000).map(|_| fido2_webauthn_server::utils::crypto::generate_secure_challenge().unwrap()).collect();
        
        let mut byte_counts = std::collections::HashMap::new();
        for challenge in &challenges {
            let decoded = base64::decode_config(challenge, base64::URL_SAFE_NO_PAD).unwrap();
            for byte in decoded {
                *byte_counts.entry(byte).or_insert(0) += 1;
            }
        }
        
        // Check for reasonable distribution
        let total_bytes = challenges.len() * 32; // Each challenge is 32 bytes when decoded
        let expected_per_byte = total_bytes / 256;
        
        for count in byte_counts.values() {
            let deviation = (*count as f64 - expected_per_byte as f64).abs() / expected_per_byte as f64;
            assert!(deviation < 0.5, "Byte distribution should be reasonably uniform");
        }
    }

    #[test]
    fn test_csprng_usage() {
        // Test that we're using a cryptographically secure RNG
        assert!(uses_csprng_for_challenges());
    }

    #[test]
    fn test_challenge_unpredictability() {
        // Challenges should be unpredictable
        let challenge1 = fido2_webauthn_server::utils::crypto::generate_secure_challenge().unwrap();
        let challenge2 = fido2_webauthn_server::utils::crypto::generate_secure_challenge().unwrap();
        
        assert_ne!(challenge1, challenge2);
        
        // Even with same seed, challenges should be different
        // (This is more of a conceptual test since we can't control the seed)
    }

    #[test]
    fn test_base64url_safety() {
        // Ensure challenges use base64url encoding (URL-safe, no padding)
        let challenge = fido2_webauthn_server::utils::crypto::generate_secure_challenge().unwrap();
        
        // Should not contain URL-unsafe characters
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.contains('='));
        
        // Should be valid base64url
        assert!(base64::decode_config(&challenge, base64::URL_SAFE_NO_PAD).is_ok());
    }
}