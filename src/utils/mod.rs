use base64::{Engine as _, engine::general_purpose};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::Value;
use std::collections::HashSet;

/// Cryptographic and validation utilities

/// Generate a cryptographically secure random challenge
pub fn generate_challenge() -> String {
    let mut rng = rand::thread_rng();
    let challenge: String = (0..32)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes())
}

/// Validate base64url encoding
pub fn validate_base64url(input: &str) -> Result<Vec<u8>, crate::error::Fido2Error> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| crate::error::Fido2Error::InvalidBase64Url)
}

/// Extract challenge from client data JSON
pub fn extract_challenge_from_client_data(client_data_json: &str) -> Result<String, crate::error::Fido2Error> {
    let client_data: Value = serde_json::from_str(client_data_json)
        .map_err(|_| crate::error::Fido2Error::InvalidRequest)?;
    
    client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| crate::error::Fido2Error::InvalidRequest)
}

/// Validate RP ID against origin
pub fn validate_rp_id(rp_id: &str, origin: &str) -> bool {
    // Simple validation - in production, this should be more sophisticated
    origin.contains(rp_id) && origin.starts_with("https://")
}

/// Check for replay attacks using a set of used challenges
pub fn check_replay_attack(challenge: &str, used_challenges: &mut HashSet<String>) -> Result<(), crate::error::Fido2Error> {
    if used_challenges.contains(challenge) {
        return Err(crate::error::Fido2Error::ReplayAttack);
    }
    used_challenges.insert(challenge.to_string());
    Ok(())
}

/// Validate credential ID format
pub fn validate_credential_id(credential_id: &str) -> Result<(), crate::error::Fido2Error> {
    if credential_id.is_empty() {
        return Err(crate::error::Fido2Error::Validation("Credential ID cannot be empty".to_string()));
    }
    
    if credential_id.len() > 1023 {
        return Err(crate::error::Fido2Error::Validation("Credential ID too long".to_string()));
    }
    
    // Validate base64url format
    validate_base64url(credential_id).map(|_| ())
}

/// Validate username format
pub fn validate_username(username: &str) -> Result<(), crate::error::Fido2Error> {
    if username.is_empty() {
        return Err(crate::error::Fido2Error::Validation("Username cannot be empty".to_string()));
    }
    
    if username.len() > 255 {
        return Err(crate::error::Fido2Error::Validation("Username too long".to_string()));
    }
    
    // Allow alphanumeric, underscores, and hyphens
    let valid_chars = username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-');
    if !valid_chars {
        return Err(crate::error::Fido2Error::Validation("Username contains invalid characters".to_string()));
    }
    
    Ok(())
}

/// Validate display name format
pub fn validate_display_name(display_name: &str) -> Result<(), crate::error::Fido2Error> {
    if display_name.is_empty() {
        return Err(crate::error::Fido2Error::Validation("Display name cannot be empty".to_string()));
    }
    
    if display_name.len() > 255 {
        return Err(crate::error::Fido2Error::Validation("Display name too long".to_string()));
    }
    
    // Allow most Unicode characters for display names
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        // Challenges should be different
        assert_ne!(challenge1, challenge2);
        
        // Should be valid base64url
        assert!(validate_base64url(&challenge1).is_ok());
        assert!(validate_base64url(&challenge2).is_ok());
        
        // Should be reasonable length
        assert!(challenge1.len() >= 16);
        assert!(challenge1.len() <= 64);
    }

    #[test]
    fn test_validate_base64url() {
        // Valid base64url
        let valid = "dGVzdA";
        assert!(validate_base64url(valid).is_ok());
        
        // Invalid base64url (contains padding)
        let invalid = "dGVzdA==";
        assert!(validate_base64url(invalid).is_err());
        
        // Invalid base64url (invalid characters)
        let invalid = "test+/";
        assert!(validate_base64url(invalid).is_err());
    }

    #[test]
    fn test_extract_challenge_from_client_data() {
        let valid_client_data = r#"{"challenge":"test_challenge","origin":"https://example.com"}"#;
        let challenge = extract_challenge_from_client_data(valid_client_data).unwrap();
        assert_eq!(challenge, "test_challenge");
        
        // Invalid JSON
        let invalid_json = "not json";
        assert!(extract_challenge_from_client_data(invalid_json).is_err());
        
        // Missing challenge
        let no_challenge = r#"{"origin":"https://example.com"}"#;
        assert!(extract_challenge_from_client_data(no_challenge).is_err());
    }

    #[test]
    fn test_validate_rp_id() {
        // Valid cases
        assert!(validate_rp_id("example.com", "https://example.com"));
        assert!(validate_rp_id("example.com", "https://example.com/auth"));
        assert!(validate_rp_id("sub.example.com", "https://sub.example.com"));
        
        // Invalid cases
        assert!(!validate_rp_id("example.com", "http://example.com"));
        assert!(!validate_rp_id("example.com", "https://malicious.com"));
        assert!(!validate_rp_id("example.com", "ftp://example.com"));
    }

    #[test]
    fn test_replay_attack_detection() {
        let mut used_challenges = HashSet::new();
        let challenge = "test_challenge";
        
        // First use should succeed
        assert!(check_replay_attack(challenge, &mut used_challenges).is_ok());
        
        // Second use should fail
        assert!(matches!(
            check_replay_attack(challenge, &mut used_challenges),
            Err(crate::error::Fido2Error::ReplayAttack)
        ));
    }

    #[test]
    fn test_validate_credential_id() {
        // Valid credential ID
        let valid_id = "dGVzdF9jcmVkZW50aWFsX2lk";
        assert!(validate_credential_id(valid_id).is_ok());
        
        // Empty credential ID
        assert!(validate_credential_id("").is_err());
        
        // Too long credential ID
        let long_id = "a".repeat(1024);
        assert!(validate_credential_id(&long_id).is_err());
        
        // Invalid base64url
        assert!(validate_credential_id("invalid+base64").is_err());
    }

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("alice_smith").is_ok());
        assert!(validate_username("alice-smith").is_ok());
        assert!(validate_username("user123").is_ok());
        
        // Invalid usernames
        assert!(validate_username("").is_err());
        assert!(validate_username("a".repeat(256).as_str()).is_err());
        assert!(validate_username("alice@smith").is_err());
        assert!(validate_username("alice smith").is_err());
    }

    #[test]
    fn test_validate_display_name() {
        // Valid display names
        assert!(validate_display_name("Alice Smith").is_ok());
        assert!(validate_display_name("Alice").is_ok());
        assert!(validate_display_name("用户").is_ok()); // Unicode characters
        
        // Invalid display names
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("a".repeat(256).as_str()).is_err());
    }

    #[test]
    fn test_challenge_uniqueness() {
        let mut challenges = HashSet::new();
        
        // Generate 1000 challenges and check uniqueness
        for _ in 0..1000 {
            let challenge = generate_challenge();
            assert!(!challenges.contains(&challenge));
            challenges.insert(challenge);
        }
        
        assert_eq!(challenges.len(), 1000);
    }
}