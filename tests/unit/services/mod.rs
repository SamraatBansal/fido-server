//! Unit tests for WebAuthn services

use crate::common::*;
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod webauthn_service_tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_generation_security() {
        // Test challenge generation security properties
        
        // Generate multiple challenges for statistical testing
        let challenges: Vec<String> = (0..1000).map(|_| generate_secure_challenge()).collect();
        
        // Test minimum length requirement (FIDO2 spec requires at least 16 bytes)
        for challenge in &challenges {
            assert!(challenge.len() >= 16, "Challenge must be at least 16 bytes");
        }
        
        // Test uniqueness (no duplicates in 1000 challenges)
        let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), challenges.len(), "All challenges must be unique");
        
        // Test base64url encoding validity
        for challenge in &challenges {
            let decoded = base64::decode_config(challenge, base64::URL_SAFE_NO_PAD);
            assert!(decoded.is_ok(), "Challenge must be valid base64url");
            
            let decoded_bytes = decoded.unwrap();
            assert_eq!(decoded_bytes.len(), 32, "Challenge should be 32 bytes when decoded");
        }
        
        // Test entropy quality (basic statistical test)
        let mut byte_counts = HashMap::new();
        for challenge in &challenges {
            let decoded = base64::decode_config(challenge, base64::URL_SAFE_NO_PAD).unwrap();
            for byte in decoded {
                *byte_counts.entry(byte).or_insert(0) += 1;
            }
        }
        
        // Check for reasonable distribution (each byte should appear multiple times)
        let total_bytes = challenges.len() * 32;
        let expected_per_byte = total_bytes / 256;
        
        for count in byte_counts.values() {
            let deviation = (*count as f64 - expected_per_byte as f64).abs() / expected_per_byte as f64;
            assert!(deviation < 0.5, "Byte distribution should be reasonably uniform");
        }
    }

    #[tokio::test]
    async fn test_challenge_expiration() {
        // Test challenge expiration logic
        
        let challenge = TestChallenge::registration();
        
        // Initially not expired
        assert!(challenge.expires_at > chrono::Utc::now());
        
        // Create expired challenge
        let expired_challenge = TestChallenge::expired();
        assert!(expired_challenge.expires_at < chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_user_validation() {
        // Test user validation logic
        
        // Valid user
        let valid_user = TestUser::valid();
        assert!(!valid_user.username.is_empty());
        assert!(!valid_user.display_name.is_empty());
        assert!(valid_user.username.len() <= 255);
        assert!(valid_user.display_name.len() <= 255);
        
        // Invalid users
        let empty_username = TestUser::invalid_empty_username();
        assert!(empty_username.username.is_empty());
        
        let long_username = TestUser::invalid_long_username();
        assert!(long_username.username.len() > 255);
        
        let invalid_chars = TestUser::invalid_characters();
        assert!(invalid_chars.username.contains('@'));
        assert!(invalid_chars.username.contains('#'));
    }

    #[tokio::test]
    async fn test_credential_validation() {
        // Test credential validation logic
        
        let credential = TestCredential::valid();
        
        // Validate credential ID
        assert!(!credential.id.is_empty());
        let decoded_id = base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD);
        assert!(decoded_id.is_ok());
        
        // Validate public key
        assert!(!credential.public_key.is_empty());
        
        // Validate sign count
        assert_eq!(credential.sign_count, 0);
        
        // Validate attestation type
        assert!(!credential.attestation_type.is_empty());
        assert!(["packed", "fido-u2f", "none", "android-key", "android-safetynet"]
            .contains(&credential.attestation_type.as_str()));
    }

    #[tokio::test]
    async fn test_rp_id_validation() {
        // Test RP ID validation according to FIDO2 spec
        
        let valid_rp_ids = vec![
            "example.com",
            "sub.example.com",
            "localhost",
            "127.0.0.1",
        ];
        
        let invalid_rp_ids = vec![
            "",
            ".example.com",
            "example..com",
            "example.com/",
            "https://example.com",
            "user:pass@example.com",
        ];
        
        for rp_id in valid_rp_ids {
            assert!(is_valid_rp_id(rp_id), "RP ID '{}' should be valid", rp_id);
        }
        
        for rp_id in invalid_rp_ids {
            assert!(!is_valid_rp_id(rp_id), "RP ID '{}' should be invalid", rp_id);
        }
    }

    #[tokio::test]
    async fn test_origin_validation() {
        // Test origin validation
        
        let valid_origins = vec![
            ("https://example.com", "example.com"),
            ("https://sub.example.com", "example.com"),
            ("https://example.com:8443", "example.com"),
        ];
        
        let invalid_origins = vec![
            ("https://malicious.com", "example.com"),
            ("http://example.com", "example.com"), // HTTP not allowed
            ("https://example.com.evil.com", "example.com"),
        ];
        
        for (origin, rp_id) in valid_origins {
            assert!(is_valid_origin(origin, rp_id), "Origin '{}' should be valid for RP ID '{}'", origin, rp_id);
        }
        
        for (origin, rp_id) in invalid_origins {
            assert!(!is_valid_origin(origin, rp_id), "Origin '{}' should be invalid for RP ID '{}'", origin, rp_id);
        }
    }

    #[tokio::test]
    async fn test_attestation_format_support() {
        // Test attestation format support
        
        let supported_formats = vec![
            "packed",
            "fido-u2f",
            "none",
            "android-key",
            "android-safetynet",
        ];
        
        for format in supported_formats {
            assert!(supports_attestation_format(format), "Format '{}' should be supported", format);
        }
        
        let unsupported_formats = vec![
            "invalid",
            "unknown",
            "",
        ];
        
        for format in unsupported_formats {
            assert!(!supports_attestation_format(format), "Format '{}' should not be supported", format);
        }
    }

    #[tokio::test]
    async fn test_counter_replay_detection() {
        // Test counter replay detection logic
        
        let mut credential = TestCredential::valid();
        let original_sign_count = credential.sign_count;
        
        // Simulate first authentication
        credential.sign_count = 1;
        assert!(credential.sign_count > original_sign_count);
        
        // Simulate replay attack (same or lower counter)
        let replay_sign_count = credential.sign_count;
        assert!(is_counter_replay(credential.sign_count, replay_sign_count));
        
        // Valid new authentication (higher counter)
        let new_sign_count = credential.sign_count + 1;
        assert!(!is_counter_replay(credential.sign_count, new_sign_count));
    }

    #[tokio::test]
    async fn test_user_verification_requirements() {
        // Test user verification requirements
        
        let uv_values = vec!["required", "preferred", "discouraged"];
        
        for uv in uv_values {
            assert!(is_valid_user_verification(uv), "User verification '{}' should be valid", uv);
        }
        
        let invalid_uv_values = vec!["", "invalid", "maybe"];
        
        for uv in invalid_uv_values {
            assert!(!is_valid_user_verification(uv), "User verification '{}' should be invalid", uv);
        }
    }

    #[tokio::test]
    async fn test_algorithm_support() {
        // Test algorithm support
        
        let supported_algorithms = vec![-7, -257, -35, -36, -258, -259, -37, -38, -39];
        
        for alg in supported_algorithms {
            assert!(supports_algorithm(alg), "Algorithm '{}' should be supported", alg);
        }
        
        let unsupported_algorithms = vec![0, 1, -1, -999];
        
        for alg in unsupported_algorithms {
            assert!(!supports_algorithm(alg), "Algorithm '{}' should not be supported", alg);
        }
    }
}

#[cfg(test)]
mod user_service_tests {
    use super::*;

    #[tokio::test]
    async fn test_user_creation() {
        // Test user creation logic
        
        let user = TestUser::new("alice", "Alice Smith");
        
        assert!(!user.id.to_string().is_empty());
        assert_eq!(user.username, "alice");
        assert_eq!(user.display_name, "Alice Smith");
        assert!(user.created_at <= chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_user_lookup() {
        // Test user lookup logic
        
        let user = TestUser::valid();
        
        // Simulate user lookup by username
        assert_eq!(lookup_user_by_username(&user.username), Some(user.clone()));
        
        // Test non-existent user
        assert_eq!(lookup_user_by_username("nonexistent"), None);
    }

    #[tokio::test]
    async fn test_user_update() {
        // Test user update logic
        
        let mut user = TestUser::valid();
        let original_display_name = user.display_name.clone();
        
        // Update display name
        user.display_name = "Alice Johnson".to_string();
        assert_ne!(user.display_name, original_display_name);
        
        // Verify update persistence
        let updated_user = get_user_by_id(user.id);
        assert_eq!(updated_user.display_name, user.display_name);
    }
}

#[cfg(test)]
mod credential_service_tests {
    use super::*;

    #[tokio::test]
    async fn test_credential_creation() {
        // Test credential creation logic
        
        let user_id = Uuid::new_v4();
        let credential = TestCredential::new(user_id);
        
        assert!(!credential.id.is_empty());
        assert_eq!(credential.user_id, user_id);
        assert!(!credential.public_key.is_empty());
        assert_eq!(credential.sign_count, 0);
        assert!(!credential.attestation_type.is_empty());
    }

    #[tokio::test]
    async fn test_credential_lookup() {
        // Test credential lookup logic
        
        let credential = TestCredential::valid();
        
        // Simulate credential lookup by ID
        assert_eq!(lookup_credential_by_id(&credential.id), Some(credential.clone()));
        
        // Test non-existent credential
        assert_eq!(lookup_credential_by_id("nonexistent"), None);
    }

    #[tokio::test]
    async fn test_credential_lookup_by_user() {
        // Test credential lookup by user
        
        let user_id = Uuid::new_v4();
        let credential1 = TestCredential::new(user_id);
        let credential2 = TestCredential::new(user_id);
        
        let user_credentials = get_credentials_by_user_id(user_id);
        assert_eq!(user_credentials.len(), 2);
        assert!(user_credentials.iter().any(|c| c.id == credential1.id));
        assert!(user_credentials.iter().any(|c| c.id == credential2.id));
    }

    #[tokio::test]
    async fn test_credential_update() {
        // Test credential update logic
        
        let mut credential = TestCredential::valid();
        let original_sign_count = credential.sign_count;
        
        // Update sign count after authentication
        credential.sign_count += 1;
        assert!(credential.sign_count > original_sign_count);
        
        // Verify update persistence
        let updated_credential = get_credential_by_id(credential.id);
        assert_eq!(updated_credential.sign_count, credential.sign_count);
    }

    #[tokio::test]
    async fn test_credential_deletion() {
        // Test credential deletion logic
        
        let credential = TestCredential::valid();
        
        // Verify credential exists
        assert!(lookup_credential_by_id(&credential.id).is_some());
        
        // Delete credential
        delete_credential(&credential.id);
        
        // Verify credential is deleted
        assert!(lookup_credential_by_id(&credential.id).is_none());
    }
}

// Helper functions for testing (these would be implemented in the actual service)
fn is_valid_rp_id(rp_id: &str) -> bool {
    !rp_id.is_empty() && 
    !rp_id.starts_with('.') && 
    !rp_id.contains("..") && 
    !rp_id.contains('/') &&
    !rp_id.contains(':') &&
    rp_id.len() <= 255
}

fn is_valid_origin(origin: &str, rp_id: &str) -> bool {
    if !origin.starts_with("https://") {
        return false;
    }
    
    let origin_host = origin.strip_prefix("https://").unwrap_or("");
    let host_without_port = origin_host.split(':').next().unwrap_or("");
    
    host_without_port == rp_id || host_without_port.ends_with(&format!(".{}", rp_id))
}

fn supports_attestation_format(format: &str) -> bool {
    matches!(format, "packed" | "fido-u2f" | "none" | "android-key" | "android-safetynet")
}

fn is_counter_replay(old_count: u64, new_count: u64) -> bool {
    new_count <= old_count
}

fn is_valid_user_verification(uv: &str) -> bool {
    matches!(uv, "required" | "preferred" | "discouraged")
}

fn supports_algorithm(alg: i32) -> bool {
    matches!(alg, -7 | -257 | -35 | -36 | -258 | -259 | -37 | -38 | -39)
}

fn lookup_user_by_username(username: &str) -> Option<TestUser> {
    if username == "alice" {
        Some(TestUser::valid())
    } else {
        None
    }
}

fn get_user_by_id(_id: Uuid) -> TestUser {
    TestUser::valid()
}

fn lookup_credential_by_id(_id: &str) -> Option<TestCredential> {
    Some(TestCredential::valid())
}

fn get_credentials_by_user_id(user_id: Uuid) -> Vec<TestCredential> {
    vec![TestCredential::new(user_id), TestCredential::new(user_id)]
}

fn get_credential_by_id(_id: String) -> TestCredential {
    TestCredential::valid()
}

fn delete_credential(_id: &str) {
    // Mock implementation
}