//! Unit tests for utility functions

use fido2_webauthn_server::utils::{crypto, validation};

#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_generate_secure_challenge() {
        let challenge1 = crypto::generate_secure_challenge();
        let challenge2 = crypto::generate_secure_challenge();
        
        assert_ne!(challenge1, challenge2, "Challenges should be unique");
        assert!(challenge1.len() >= 16, "Challenge should be at least 16 characters");
        assert!(challenge2.len() >= 16, "Challenge should be at least 16 characters");
        
        // Should be valid base64url
        assert!(crypto::decode_base64url(&challenge1).is_ok(), "Challenge should be valid base64url");
        assert!(crypto::decode_base64url(&challenge2).is_ok(), "Challenge should be valid base64url");
    }

    #[test]
    fn test_generate_user_id() {
        let user_id1 = crypto::generate_user_id();
        let user_id2 = crypto::generate_user_id();
        
        assert_ne!(user_id1, user_id2, "User IDs should be unique");
        assert!(user_id1.len() >= 16, "User ID should be at least 16 characters");
        
        // Should be valid base64url
        assert!(crypto::decode_base64url(&user_id1).is_ok(), "User ID should be valid base64url");
        assert!(crypto::decode_base64url(&user_id2).is_ok(), "User ID should be valid base64url");
    }

    #[test]
    fn test_generate_credential_id() {
        let cred_id1 = crypto::generate_credential_id();
        let cred_id2 = crypto::generate_credential_id();
        
        assert_ne!(cred_id1, cred_id2, "Credential IDs should be unique");
        assert!(cred_id1.len() >= 16, "Credential ID should be at least 16 characters");
        
        // Should be valid base64url
        assert!(crypto::decode_base64url(&cred_id1).is_ok(), "Credential ID should be valid base64url");
        assert!(crypto::decode_base64url(&cred_id2).is_ok(), "Credential ID should be valid base64url");
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash1 = crypto::sha256_hash(data);
        let hash2 = crypto::sha256_hash(data);
        
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 should produce 32 bytes");
        
        // Different data should produce different hashes
        let hash3 = crypto::sha256_hash(b"different data");
        assert_ne!(hash1, hash3, "Different data should produce different hashes");
    }

    #[test]
    fn test_current_timestamp() {
        let timestamp1 = crypto::current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let timestamp2 = crypto::current_timestamp();
        
        assert!(timestamp2 > timestamp1, "Timestamp should be monotonically increasing");
        assert!(timestamp1 > 0, "Timestamp should be positive");
    }

    #[test]
    fn test_base64url_encoding_roundtrip() {
        let original_data = b"hello world, this is a test!";
        let encoded = crypto::encode_base64url(original_data);
        let decoded = crypto::decode_base64url(&encoded).unwrap();
        
        assert_eq!(decoded, original_data, "Encoding/decoding should be reversible");
    }

    #[test]
    fn test_base64url_decode_invalid() {
        let invalid_data = "invalid+base64/with=padding";
        let result = crypto::decode_base64url(invalid_data);
        
        assert!(result.is_err(), "Invalid base64url should fail to decode");
    }

    #[test]
    fn test_verify_entropy_insufficient_data() {
        let few_challenges: Vec<String> = (0..10).map(|_| crypto::generate_secure_challenge()).collect();
        assert!(!crypto::verify_entropy(&few_challenges), "Should fail with insufficient data");
    }

    #[test]
    fn test_verify_entropy_sufficient_data() {
        let many_challenges: Vec<String> = (0..1000).map(|_| crypto::generate_secure_challenge()).collect();
        assert!(crypto::verify_entropy(&many_challenges), "Should pass with sufficient data");
    }

    #[test]
    fn test_verify_entropy_invalid_data() {
        // Create challenges with low entropy (all the same)
        let low_entropy_challenges: Vec<String> = (0..100).map(|_| "AAAAAAAAAAAAAAAAAAAAAA".to_string()).collect();
        assert!(!crypto::verify_entropy(&low_entropy_challenges), "Should fail with low entropy data");
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use validator::ValidationError;

    #[test]
    fn test_validate_attestation() {
        assert!(validation::validate_attestation("none").is_ok(), "none should be valid");
        assert!(validation::validate_attestation("indirect").is_ok(), "indirect should be valid");
        assert!(validation::validate_attestation("direct").is_ok(), "direct should be valid");
        assert!(validation::validate_attestation("invalid").is_err(), "invalid should be rejected");
    }

    #[test]
    fn test_validate_user_verification() {
        assert!(validation::validate_user_verification("required").is_ok(), "required should be valid");
        assert!(validation::validate_user_verification("preferred").is_ok(), "preferred should be valid");
        assert!(validation::validate_user_verification("discouraged").is_ok(), "discouraged should be valid");
        assert!(validation::validate_user_verification("invalid").is_err(), "invalid should be rejected");
    }

    #[test]
    fn test_validate_credential_type() {
        assert!(validation::validate_credential_type("public-key").is_ok(), "public-key should be valid");
        assert!(validation::validate_credential_type("invalid").is_err(), "invalid should be rejected");
    }

    #[test]
    fn test_validate_base64url() {
        assert!(validation::validate_base64url("valid_base64url_string123").is_ok(), "valid base64url should pass");
        assert!(validation::validate_base64url("invalid+chars").is_err(), "+ should be invalid");
        assert!(validation::validate_base64url("invalid/chars").is_err(), "/ should be invalid");
        assert!(validation::validate_base64url("invalid=padding").is_err(), "= should be invalid");
    }

    #[test]
    fn test_validate_challenge() {
        // Valid challenges
        assert!(validation::validate_challenge(&"A".repeat(16)).is_ok(), "16 chars should be valid");
        assert!(validation::validate_challenge(&"A".repeat(64)).is_ok(), "64 chars should be valid");
        
        // Invalid challenges
        assert!(validation::validate_challenge("short").is_err(), "too short should be invalid");
        assert!(validation::validate_challenge(&"A".repeat(129)).is_err(), "too long should be invalid");
        assert!(validation::validate_challenge("invalid+chars").is_err(), "invalid chars should be rejected");
    }

    #[test]
    fn test_validate_credential_id() {
        // Valid credential IDs
        assert!(validation::validate_credential_id("valid_credential_id").is_ok(), "valid ID should pass");
        assert!(validation::validate_credential_id(&"A".repeat(100)).is_ok(), "long but valid ID should pass");
        
        // Invalid credential IDs
        assert!(validation::validate_credential_id("").is_err(), "empty ID should be invalid");
        assert!(validation::validate_credential_id(&"A".repeat(1024)).is_err(), "too long ID should be invalid");
        assert!(validation::validate_credential_id("invalid+chars").is_err(), "invalid chars should be rejected");
    }

    #[test]
    fn test_validate_authenticator_data() {
        // Valid authenticator data (minimum 37 bytes when base64url decoded)
        let valid_data = crypto::encode_base64url(&[0u8; 37]);
        assert!(validation::validate_authenticator_data(&valid_data).is_ok(), "minimum size should be valid");
        
        // Invalid authenticator data
        assert!(validation::validate_authenticator_data("short").is_err(), "too short should be invalid");
        assert!(validation::validate_authenticator_data("invalid+chars").is_err(), "invalid chars should be rejected");
    }

    #[test]
    fn test_validate_signature() {
        // Valid signatures
        assert!(validation::validate_signature("valid_signature").is_ok(), "valid signature should pass");
        assert!(validation::validate_signature(&"A".repeat(100)).is_ok(), "long signature should pass");
        
        // Invalid signatures
        assert!(validation::validate_signature("").is_err(), "empty signature should be invalid");
        assert!(validation::validate_signature("invalid+chars").is_err(), "invalid chars should be rejected");
    }

    #[test]
    fn test_username_regex() {
        // Valid usernames (email format as per regex)
        assert!(validation::USERNAME_REGEX.is_match("test@example.com"), "valid email should match");
        assert!(validation::USERNAME_REGEX.is_match("user.name+tag@domain.co.uk"), "complex email should match");
        
        // Invalid usernames
        assert!(!validation::USERNAME_REGEX.is_match(""), "empty should not match");
        assert!(!validation::USERNAME_REGEX.is_match("invalid-email"), "invalid email should not match");
        assert!(!validation::USERNAME_REGEX.is_match("@domain.com"), "missing user should not match");
        assert!(!validation::USERNAME_REGEX.is_match("user@"), "missing domain should not match");
    }

    #[test]
    fn test_credential_id_regex() {
        // Valid credential IDs
        assert!(validation::CREDENTIAL_ID_REGEX.is_match("valid_credential_id"), "alphanumeric should match");
        assert!(validation::CREDENTIAL_ID_REGEX.is_match("cred-id_with_underscores"), "with underscores should match");
        assert!(validation::CREDENTIAL_ID_REGEX.is_match("credIDwithMixedCASE"), "mixed case should match");
        
        // Invalid credential IDs
        assert!(!validation::CREDENTIAL_ID_REGEX.is_match(""), "empty should not match");
        assert!(!validation::CREDENTIAL_ID_REGEX.is_match("invalid+chars"), "+ should not match");
        assert!(!validation::CREDENTIAL_ID_REGEX.is_match("invalid/chars"), "/ should not match");
        assert!(!validation::CREDENTIAL_ID_REGEX.is_match("invalid=chars"), "= should not match");
    }

    #[test]
    fn test_base64url_regex() {
        // Valid base64url
        assert!(validation::BASE64URL_REGEX.is_match("valid_base64url_string"), "alphanumeric should match");
        assert!(validation::BASE64URL_REGEX.is_match("string-with_underscores"), "with underscores should match");
        
        // Invalid base64url
        assert!(!validation::BASE64URL_REGEX.is_match("invalid+chars"), "+ should not match");
        assert!(!validation::BASE64URL_REGEX.is_match("invalid/chars"), "/ should not match");
        assert!(!validation::BASE64URL_REGEX.is_match("invalid=padding"), "= should not match");
    }
}