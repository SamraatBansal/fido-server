//! Input validation security tests

#[cfg(test)]
mod tests {
    use crate::common::*;
    use fido2_webauthn_server::utils::validation::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_challenge_validation() {
        // Valid challenges
        let valid_challenge = generate_secure_challenge();
        assert!(validate_challenge(&valid_challenge));
        
        // Invalid challenges
        assert!(!validate_challenge(""));
        assert!(!validate_challenge("too_short"));
        assert!(!validate_challenge("invalid_base64!!!"));
    }

    #[test]
    fn test_credential_id_validation() {
        // Valid credential IDs
        let valid_credential_id = URL_SAFE_NO_PAD.encode(&[1, 2, 3, 4]);
        assert!(validate_credential_id(&valid_credential_id));
        
        // Invalid credential IDs
        assert!(!validate_credential_id(""));
        assert!(!validate_credential_id("invalid_base64!!!"));
        
        // Too long credential ID
        let too_long = "a".repeat(1025);
        assert!(!validate_credential_id(&too_long));
    }

    #[test]
    fn test_rp_id_validation() {
        // Valid RP IDs
        assert!(validate_rp_id("example.com"));
        assert!(validate_rp_id("localhost"));
        assert!(validate_rp_id("webauthn.example.com"));
        
        // Invalid RP IDs
        assert!(!validate_rp_id(""));
        assert!(!validate_rp_id("invalid"));
        assert!(!validate_rp_id(&"a".repeat(256)));
    }

    #[test]
    fn test_origin_validation() {
        // Valid origins
        assert!(validate_origin("https://example.com", "example.com"));
        assert!(validate_origin("https://webauthn.example.com", "example.com"));
        
        // Invalid origins
        assert!(!validate_origin("http://example.com", "example.com")); // HTTP not allowed
        assert!(!validate_origin("https://malicious.com", "example.com")); // Wrong domain
        assert!(!validate_origin("https://example.com", "malicious.com")); // Wrong RP ID
    }

    #[test]
    fn test_attestation_format_validation() {
        // Supported formats
        assert!(supports_attestation_format("packed"));
        assert!(supports_attestation_format("fido-u2f"));
        assert!(supports_attestation_format("none"));
        assert!(supports_attestation_format("android-key"));
        assert!(supports_attestation_format("android-safetynet"));
        
        // Unsupported formats
        assert!(!supports_attestation_format("unsupported"));
        assert!(!supports_attestation_format(""));
    }

    #[test]
    fn test_user_verification_validation() {
        // Valid values
        assert!(validate_user_verification("required"));
        assert!(validate_user_verification("preferred"));
        assert!(validate_user_verification("discouraged"));
        
        // Invalid values
        assert!(!validate_user_verification("invalid"));
        assert!(!validate_user_verification(""));
    }

    #[test]
    fn test_algorithm_support() {
        // Supported algorithms
        assert!(is_supported_algorithm(-7));   // ES256
        assert!(is_supported_algorithm(-257)); // RS256
        assert!(is_supported_algorithm(-35));  // EdDSA (if supported)
        
        // Unsupported algorithms
        assert!(!is_supported_algorithm(-999));
        assert!(!is_supported_algorithm(0));
    }

    #[test]
    fn test_cipher_suite_validation() {
        // Strong cipher suites
        assert!(is_strong_cipher_suite("TLS_AES_256_GCM_SHA384"));
        assert!(is_strong_cipher_suite("TLS_CHACHA20_POLY1305_SHA256"));
        assert!(is_strong_cipher_suite("TLS_AES_128_GCM_SHA256"));
        
        // Weak cipher suites
        assert!(!is_strong_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA"));
        assert!(!is_strong_cipher_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
    }
}