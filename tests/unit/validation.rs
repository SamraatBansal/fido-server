//! Unit tests for validation utilities

use fido2_webauthn_server::utils::validation;
use validator::ValidationError;

#[cfg(test)]
mod validation_function_tests {
    use super::*;

    #[test]
    fn test_attestation_validation_all_values() {
        // Test all valid attestation values
        let valid_values = ["none", "indirect", "direct"];
        
        for value in &valid_values {
            assert!(
                validation::validate_attestation(value).is_ok(),
                "Attestation value '{}' should be valid",
                value
            );
        }
    }

    #[test]
    fn test_attestation_validation_case_sensitivity() {
        // Test case sensitivity
        assert!(validation::validate_attestation("NONE").is_err(), "Uppercase should be invalid");
        assert!(validation::validate_attestation("None").is_err(), "Mixed case should be invalid");
        assert!(validation::validate_attestation("DIRECT").is_err(), "Uppercase should be invalid");
    }

    #[test]
    fn test_user_verification_validation_all_values() {
        // Test all valid user verification values
        let valid_values = ["required", "preferred", "discouraged"];
        
        for value in &valid_values {
            assert!(
                validation::validate_user_verification(value).is_ok(),
                "User verification value '{}' should be valid",
                value
            );
        }
    }

    #[test]
    fn test_user_verification_validation_case_sensitivity() {
        // Test case sensitivity
        assert!(validation::validate_user_verification("REQUIRED").is_err(), "Uppercase should be invalid");
        assert!(validation::validate_user_verification("Preferred").is_err(), "Mixed case should be invalid");
    }

    #[test]
    fn test_credential_type_validation() {
        // Test valid credential type
        assert!(validation::validate_credential_type("public-key").is_ok(), "public-key should be valid");
        
        // Test invalid credential types
        let invalid_types = ["", "publickey", "public_key", "PUBLIC-KEY", "invalid"];
        
        for cred_type in &invalid_types {
            assert!(
                validation::validate_credential_type(cred_type).is_err(),
                "Credential type '{}' should be invalid",
                cred_type
            );
        }
    }

    #[test]
    fn test_challenge_validation_boundary_values() {
        // Test minimum valid length (16 characters)
        let min_valid = "A".repeat(16);
        assert!(validation::validate_challenge(&min_valid).is_ok(), "16 characters should be valid");
        
        // Test maximum valid length (128 characters)
        let max_valid = "A".repeat(128);
        assert!(validation::validate_challenge(&max_valid).is_ok(), "128 characters should be valid");
        
        // Test just below minimum
        let too_short = "A".repeat(15);
        assert!(validation::validate_challenge(&too_short).is_err(), "15 characters should be invalid");
        
        // Test just above maximum
        let too_long = "A".repeat(129);
        assert!(validation::validate_challenge(&too_long).is_err(), "129 characters should be invalid");
    }

    #[test]
    fn test_challenge_validation_with_valid_base64url() {
        // Test with valid base64url characters
        let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        assert!(validation::validate_challenge(valid_chars).is_ok(), "Valid base64url chars should pass");
        
        // Test with valid base64url of exact length
        let exact_length = "A".repeat(16);
        assert!(validation::validate_challenge(&exact_length).is_ok(), "Exact length should pass");
    }

    #[test]
    fn test_challenge_validation_with_invalid_base64url() {
        // Test with invalid base64url characters
        let invalid_chars_sets = [
            "ABC+DEF", // Contains +
            "ABC/DEF", // Contains /
            "ABC=DEF", // Contains =
            "ABC DEF", // Contains space
            "ABC\tDEF", // Contains tab
            "ABC\nDEF", // Contains newline
        ];
        
        for invalid_chars in &invalid_chars_sets {
            assert!(
                validation::validate_challenge(invalid_chars).is_err(),
                "Challenge with invalid chars '{}' should be rejected",
                invalid_chars
            );
        }
    }

    #[test]
    fn test_credential_id_validation_boundary_values() {
        // Test minimum valid length (1 character)
        assert!(validation::validate_credential_id("A").is_ok(), "1 character should be valid");
        
        // Test maximum valid length (1023 characters)
        let max_valid = "A".repeat(1023);
        assert!(validation::validate_credential_id(&max_valid).is_ok(), "1023 characters should be valid");
        
        // Test just above maximum
        let too_long = "A".repeat(1024);
        assert!(validation::validate_credential_id(&too_long).is_err(), "1024 characters should be invalid");
    }

    #[test]
    fn test_credential_id_validation_empty() {
        assert!(validation::validate_credential_id("").is_err(), "Empty credential ID should be invalid");
    }

    #[test]
    fn test_authenticator_data_validation_minimum_size() {
        // Test minimum valid size (37 bytes when base64url decoded)
        // 37 bytes of zeros = base64url encoded string
        let min_valid_bytes = [0u8; 37];
        let min_valid_base64url = fido2_webauthn_server::utils::crypto::encode_base64url(&min_valid_bytes);
        assert!(validation::validate_authenticator_data(&min_valid_base64url).is_ok(), 
                "Minimum size authenticator data should be valid");
        
        // Test just below minimum (36 bytes)
        let too_small_bytes = [0u8; 36];
        let too_small_base64url = fido2_webauthn_server::utils::crypto::encode_base64url(&too_small_bytes);
        assert!(validation::validate_authenticator_data(&too_small_base64url).is_err(), 
                "Too small authenticator data should be invalid");
    }

    #[test]
    fn test_signature_validation_empty() {
        assert!(validation::validate_signature("").is_err(), "Empty signature should be invalid");
    }

    #[test]
    fn test_signature_validation_non_empty() {
        // Test non-empty signatures
        let valid_signatures = [
            "A", // Single character
            "valid_signature", // Normal signature
            &"A".repeat(100), // Long signature
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", // Valid base64url
        ];
        
        for signature in valid_signatures {
            assert!(
                validation::validate_signature(signature).is_ok(),
                "Non-empty signature '{}' should be valid",
                signature
            );
        }
    }

    #[test]
    fn test_signature_validation_invalid_base64url() {
        let invalid_signatures = [
            "invalid+signature", // Contains +
            "invalid/signature", // Contains /
            "invalid=signature", // Contains =
            "invalid signature", // Contains space
        ];
        
        for signature in invalid_signatures {
            assert!(
                validation::validate_signature(signature).is_err(),
                "Signature with invalid chars '{}' should be rejected",
                signature
            );
        }
    }
}

#[cfg(test)]
mod regex_tests {
    use super::*;

    #[test]
    fn test_username_regex_email_patterns() {
        // Valid email patterns
        let valid_emails = [
            "simple@example.com",
            "very.common@example.com",
            "disposable.style.email.with+symbol@example.com",
            "other.email-with-hyphen@example.com",
            "fully-qualified-domain@example.com",
            "user.name+tag+sorting@example.com",
            "x@example.com",
            "example-indeed@strange-example.com",
            "admin@mailserver1", // Local domain
            "example@s.example",
            "mailhost!username@example.org",
            "user%example.com@example.org",
        ];
        
        for email in valid_emails {
            assert!(
                validation::USERNAME_REGEX.is_match(email),
                "Email '{}' should match username regex",
                email
            );
        }
    }

    #[test]
    fn test_username_regex_invalid_patterns() {
        // Invalid email patterns
        let invalid_emails = [
            "",
            "Abc.example.com", // No @
            "A@b@c@example.com", // Multiple @
            "a\"b(c)d,e:f;g<h>i[j\\k]l@example.com", // Invalid characters
            "just\"not\"right@example.com", // Invalid characters
            "this is\"not\\allowed@example.com", // Invalid characters
            "i_like_underscore@but_its_not_allowed_in_this_part.com", // Invalid in domain
            "user@.invalid.com", // Starts with dot
            "user@invalid-.com", // Ends with hyphen
            "user@-invalid.com", // Starts with hyphen
            "user@invalid..com", // Double dots
        ];
        
        for email in invalid_emails {
            assert!(
                !validation::USERNAME_REGEX.is_match(email),
                "Invalid email '{}' should not match username regex",
                email
            );
        }
    }

    #[test]
    fn test_credential_id_regex_patterns() {
        // Valid credential ID patterns
        let valid_ids = [
            "a",
            "credential_id",
            "credential-id",
            "credential_id",
            "CREDENTIAL_ID",
            "123456789",
            "aBcDeF123",
            "credential_with_underscores_and_numbers_123",
            &"A".repeat(100), // Long but valid
        ];
        
        for id in valid_ids {
            assert!(
                validation::CREDENTIAL_ID_REGEX.is_match(id),
                "Credential ID '{}' should match regex",
                id
            );
        }
        
        // Invalid credential ID patterns
        let invalid_ids = [
            "",
            "credential+id", // Contains +
            "credential/id", // Contains /
            "credential=id", // Contains =
            "credential id", // Contains space
            "credential\tid", // Contains tab
            "credential\nid", // Contains newline
            "credential@id", // Contains @
            "credential#id", // Contains #
            "credential%id", // Contains %
        ];
        
        for id in invalid_ids {
            assert!(
                !validation::CREDENTIAL_ID_REGEX.is_match(id),
                "Invalid credential ID '{}' should not match regex",
                id
            );
        }
    }

    #[test]
    fn test_base64url_regex_patterns() {
        // Valid base64url patterns
        let valid_base64url = [
            "A",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789",
            "-_",
            "ValidBase64UrlString123",
            "valid-base64_url_string",
            "VALIDBASE64URLSTRING",
            "1234567890",
            &"A".repeat(100), // Long but valid
        ];
        
        for base64 in valid_base64url {
            assert!(
                validation::BASE64URL_REGEX.is_match(base64),
                "Base64url '{}' should match regex",
                base64
            );
        }
        
        // Invalid base64url patterns
        let invalid_base64url = [
            "",
            "invalid+base64", // Contains +
            "invalid/base64", // Contains /
            "invalid=base64", // Contains =
            "invalid base64", // Contains space
            "invalid\tbase64", // Contains tab
            "invalid\nbase64", // Contains newline
            "invalid@base64", // Contains @
            "invalid#base64", // Contains #
            "invalid%base64", // Contains %
        ];
        
        for base64 in invalid_base64url {
            assert!(
                !validation::BASE64URL_REGEX.is_match(base64),
                "Invalid base64url '{}' should not match regex",
                base64
            );
        }
    }
}

#[cfg(test)]
mod error_message_tests {
    use super::*;

    #[test]
    fn test_validation_error_types() {
        // Test that validation errors return the expected error types
        let attestation_err = validation::validate_attestation("invalid").unwrap_err();
        assert_eq!(attestation_err.code, "invalid_attestation");

        let user_verification_err = validation::validate_user_verification("invalid").unwrap_err();
        assert_eq!(user_verification_err.code, "invalid_user_verification");

        let credential_type_err = validation::validate_credential_type("invalid").unwrap_err();
        assert_eq!(credential_type_err.code, "invalid_credential_type");

        let challenge_err = validation::validate_challenge("short").unwrap_err();
        assert_eq!(challenge_err.code, "invalid_challenge_length");

        let credential_id_err = validation::validate_credential_id("").unwrap_err();
        assert_eq!(credential_id_err.code, "invalid_credential_id_length");
    }

    #[test]
    fn test_validation_error_messages() {
        // Test that validation errors have meaningful messages
        let attestation_err = validation::validate_attestation("invalid").unwrap_err();
        assert!(!attestation_err.message.is_empty(), "Error message should not be empty");

        let user_verification_err = validation::validate_user_verification("invalid").unwrap_err();
        assert!(!user_verification_err.message.is_empty(), "Error message should not be empty");
    }
}