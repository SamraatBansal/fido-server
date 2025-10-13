//! Security tests for cryptographic operations

use crate::fixtures::*;
use fido2_webauthn_server::utils::crypto;
use std::time::Instant;

#[cfg(test)]
mod cryptographic_tests {
    

    #[test]
    fn test_secure_random_generation() {
        // Test that random number generation is secure
        let mut values = std::collections::HashSet::new();
        
        // Generate many random values
        for _ in 0..1000 {
            let value = crypto::generate_secure_challenge();
            assert!(!value.is_empty(), "Generated value should not be empty");
            assert!(value.len() >= 16, "Generated value should be sufficient length");
            assert!(crypto::decode_base64url(&value).is_ok(), "Should be valid base64url");
            values.insert(value);
        }
        
        // All values should be unique (very high probability)
        assert_eq!(values.len(), 1000, "All generated values should be unique");
    }

    #[test]
    fn test_entropy_quality() {
        // Generate large amount of random data for entropy testing
        let mut all_bytes = Vec::new();
        
        for _ in 0..100 {
            let challenge = crypto::generate_secure_challenge();
            let decoded = crypto::decode_base64url(&challenge).unwrap();
            all_bytes.extend_from_slice(&decoded);
        }
        
        // Test byte distribution
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
        assert!(entropy > 7.5, "Entropy should be high (> 7.5), got {}", entropy);
        
        // No byte should be extremely rare or extremely common
        let expected_count = total_bytes / 256.0;
        for count in &byte_counts {
            if *count > 0 {
                let deviation = (*count as f64 - expected_count).abs() / expected_count;
                assert!(deviation < 0.5, "Byte distribution should be uniform, deviation: {}", deviation);
            }
        }
    }

    #[test]
    fn test_hash_function_security() {
        // Test SHA-256 hash properties
        let data1 = b"test data";
        let data2 = b"different data";
        let data3 = b"test data"; // Same as data1
        
        let hash1 = crypto::sha256_hash(data1);
        let hash2 = crypto::sha256_hash(data2);
        let hash3 = crypto::sha256_hash(data3);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash3, "Same input should produce same hash");
        
        // Different input should produce different hash
        assert_ne!(hash1, hash2, "Different input should produce different hash");
        
        // Hash should be fixed length (32 bytes for SHA-256)
        assert_eq!(hash1.len(), 32, "SHA-256 should produce 32 bytes");
        assert_eq!(hash2.len(), 32, "SHA-256 should produce 32 bytes");
        
        // Hash should be deterministic
        let hash1_again = crypto::sha256_hash(data1);
        assert_eq!(hash1, hash1_again, "Hash should be deterministic");
        
        // Small change in input should produce completely different hash (avalanche effect)
        let data4 = b"test datb"; // One character different
        let hash4 = crypto::sha256_hash(data4);
        
        let mut differing_bits = 0;
        for (b1, b4) in hash1.iter().zip(hash4.iter()) {
            let xor = b1 ^ b4;
            differing_bits += xor.count_ones();
        }
        
        // Should have many differing bits (around half on average)
        assert!(differing_bits > 64, "Avalanche effect: should have many differing bits, got {}", differing_bits);
    }

    #[test]
    fn test_base64url_encoding_security() {
        // Test that base64url encoding doesn't introduce vulnerabilities
        let test_data = b"binary data with \x00 null bytes and \xff high bytes";
        
        let encoded = crypto::encode_base64url(test_data);
        let decoded = crypto::decode_base64url(&encoded).unwrap();
        
        // Should be lossless
        assert_eq!(decoded, test_data, "Base64url encoding should be lossless");
        
        // Should not contain problematic characters
        assert!(!encoded.contains('+'), "Should not contain '+'");
        assert!(!encoded.contains('/'), "Should not contain '/'");
        assert!(!encoded.contains('='), "Should not contain '='");
        assert!(!encoded.contains('\n'), "Should not contain newlines");
        assert!(!encoded.contains('\r'), "Should not contain carriage returns");
        
        // Should be URL-safe
        assert!(encoded.is_ascii(), "Should be ASCII only");
        assert!(!encoded.chars().any(|c| c.is_whitespace()), "Should not contain whitespace");
    }

    #[test]
    fn test_timestamp_monotonicity() {
        // Test that timestamps are monotonic
        let mut last_timestamp = 0u64;
        
        for _ in 0..10 {
            let current_timestamp = crypto::current_timestamp();
            assert!(current_timestamp >= last_timestamp, "Timestamps should be monotonic");
            last_timestamp = current_timestamp;
            
            // Small delay to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        
        // Timestamp should be reasonable (not in the distant future or past)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let timestamp = crypto::current_timestamp();
        
        // Should be within reasonable range of current time (±1 second)
        assert!(timestamp > now - 1000, "Timestamp should not be too far in the past");
        assert!(timestamp < now + 1000, "Timestamp should not be too far in the future");
    }

    #[test]
    fn test_memory_safety() {
        // Test that cryptographic operations don't leave sensitive data in memory
        // This is a basic test; in practice, you'd use more sophisticated techniques
        
        let sensitive_data = b"sensitive information";
        let hash = crypto::sha256_hash(sensitive_data);
        
        // Hash should not contain the original data
        let hash_str = format!("{:?}", hash);
        assert!(!hash_str.contains("sensitive"), "Hash should not contain original data");
        
        // Test with multiple operations
        for _ in 0..100 {
            let challenge = crypto::generate_secure_challenge();
            let decoded = crypto::decode_base64url(&challenge).unwrap();
            
            // Should be able to decode without errors
            assert!(!decoded.is_empty(), "Decoded challenge should not be empty");
        }
    }

    #[test]
    fn test_side_channel_resistance() {
        // Basic test for timing attacks on validation functions
        use std::time::Instant;
        
        let valid_challenge = crypto::generate_secure_challenge();
        let invalid_challenge = "invalid+challenge";
        
        // Time validation of valid challenge
        let start = Instant::now();
        let valid_result = fido2_webauthn_server::utils::validation::validate_challenge(&valid_challenge);
        let valid_time = start.elapsed();
        
        // Time validation of invalid challenge
        let start = Instant::now();
        let invalid_result = fido2_webauthn_server::utils::validation::validate_challenge(invalid_challenge);
        let invalid_time = start.elapsed();
        
        // Both should complete, and timing should be relatively consistent
        assert!(valid_result.is_ok(), "Valid challenge should pass validation");
        assert!(invalid_result.is_err(), "Invalid challenge should fail validation");
        
        // Time difference should not be excessive (basic side-channel resistance)
        let time_diff = if valid_time > invalid_time {
            valid_time - invalid_time
        } else {
            invalid_time - valid_time
        };
        
        // Allow some variance but not extreme differences that could leak information
        assert!(time_diff.as_micros() < 1000, "Validation times should be consistent");
    }

    #[test]
    fn test_cryptographic_constant_time_operations() {
        // Test that comparisons don't short-circuit (basic constant-time behavior)
        let data1 = vec![1u8; 1000];
        let data2 = vec![1u8; 1000]; // Same as data1
        let data3 = vec![2u8; 1000]; // Different from data1
        
        // Time comparison of equal data
        let start = Instant::now();
        let equal = data1 == data2;
        let equal_time = start.elapsed();
        
        // Time comparison of different data (should fail at first byte but still take similar time)
        let start = Instant::now();
        let not_equal = data1 == data3;
        let not_equal_time = start.elapsed();
        
        assert!(equal, "Equal data should compare equal");
        assert!(!not_equal, "Different data should compare not equal");
        
        // In a real implementation, you'd use constant-time comparison functions
        // This is a basic test to ensure we're not obviously vulnerable
        let time_ratio = if equal_time > not_equal_time {
            equal_time.as_nanos() as f64 / not_equal_time.as_nanos() as f64
        } else {
            not_equal_time.as_nanos() as f64 / equal_time.as_nanos() as f64
        };
        
        // Time difference should not be more than 10x (allowing for some variance)
        assert!(time_ratio < 10.0, "Comparison times should be relatively consistent");
    }

    #[test]
    fn test_random_quality_across_calls() {
        // Test randomness quality across multiple calls
        let mut all_challenges = Vec::new();
        
        // Generate challenges over time to test for patterns
        for _ in 0..100 {
            let challenge = crypto::generate_secure_challenge();
            all_challenges.push(challenge);
            
            // Small delay to test timing-based randomness
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        
        // Test for autocorrelation (basic test)
        for i in 1..all_challenges.len() {
            let bytes1 = crypto::decode_base64url(&all_challenges[i-1]).unwrap();
            let bytes2 = crypto::decode_base64url(&all_challenges[i]).unwrap();
            
            // Calculate simple correlation
            let mut correlation = 0.0;
            let n = bytes1.len().min(bytes2.len());
            
            for j in 0..n {
                correlation += (bytes1[j] as f64 - 128.0) * (bytes2[j] as f64 - 128.0);
            }
            
            correlation /= n as f64;
            
            // Correlation should be close to 0 (no linear relationship)
            assert!(correlation.abs() < 1000.0, "Low correlation between consecutive challenges");
        }
        
        // Test overall entropy
        assert!(crypto::verify_entropy(&all_challenges), "Challenges should have good entropy");
    }

    #[test]
    fn test_fixture_cryptographic_quality() {
        // Test that fixtures generate cryptographically sound data
        let mut credential_ids = std::collections::HashSet::new();
        let mut user_ids = std::collections::HashSet::new();
        let mut challenges = std::collections::HashSet::new();
        
        // Generate many fixtures
        for _ in 0..100 {
            let cred_id = generate_test_credential_id();
            let user_id = generate_test_user_id();
            let challenge = generate_test_challenge();
            
            // All should be unique
            assert!(!credential_ids.contains(&cred_id), "Credential ID should be unique");
            assert!(!user_ids.contains(&user_id), "User ID should be unique");
            assert!(!challenges.contains(&challenge), "Challenge should be unique");
            
            credential_ids.insert(cred_id);
            user_ids.insert(user_id);
            challenges.insert(challenge);
        }
        
        // All should be valid base64url
        for cred_id in &credential_ids {
            assert!(crypto::decode_base64url(cred_id).is_ok(), "Credential ID should be valid base64url");
        }
        
        for user_id in &user_ids {
            assert!(crypto::decode_base64url(user_id).is_ok(), "User ID should be valid base64url");
        }
        
        for challenge in &challenges {
            assert!(crypto::decode_base64url(challenge).is_ok(), "Challenge should be valid base64url");
        }
        
        // Test entropy of fixture-generated challenges
        let challenge_vec: Vec<&String> = challenges.iter().collect();
        assert!(crypto::verify_entropy(&challenge_vec), "Fixture challenges should have good entropy");
    }
}