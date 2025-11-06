//! Utility functions for FIDO2/WebAuthn operations

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;
use base64urlsafedata::Base64UrlSafeData;
use crate::error::WebAuthnError;

/// Generate a cryptographically secure random challenge
pub fn generate_challenge() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32]; // 32 bytes = 256 bits of entropy
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate a base64url encoded user ID
pub fn generate_user_id() -> String {
    let uuid = Uuid::new_v4();
    URL_SAFE_NO_PAD.encode(uuid.as_bytes())
}

/// Encode bytes as base64url string
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url string to bytes
pub fn base64url_decode(data: &str) -> Result<Vec<u8>, WebAuthnError> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| WebAuthnError::InvalidInput(format!("Invalid base64url: {}", e)))
}

/// Decode base64url string to Base64UrlSafeData for webauthn-rs
pub fn base64url_decode_safe(data: &str) -> Result<Base64UrlSafeData, WebAuthnError> {
    Base64UrlSafeData::from_string(data)
        .map_err(|e| WebAuthnError::InvalidInput(format!("Invalid base64url: {}", e)))
}

/// Validate that a string is properly base64url encoded
pub fn validate_base64url(data: &str) -> Result<(), WebAuthnError> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| WebAuthnError::Validation("Invalid base64url encoding".to_string()))?;
    Ok(())
}

/// Validate challenge format and length
pub fn validate_challenge(challenge: &str) -> Result<(), WebAuthnError> {
    validate_base64url(challenge)?;
    
    let decoded = base64url_decode(challenge)?;
    if decoded.len() < 16 {
        return Err(WebAuthnError::Validation("Challenge too short (minimum 16 bytes)".to_string()));
    }
    if decoded.len() > 64 {
        return Err(WebAuthnError::Validation("Challenge too long (maximum 64 bytes)".to_string()));
    }
    
    Ok(())
}

/// Validate user ID format
pub fn validate_user_id(user_id: &str) -> Result<(), WebAuthnError> {
    if user_id.is_empty() {
        return Err(WebAuthnError::Validation("User ID cannot be empty".to_string()));
    }
    
    validate_base64url(user_id)?;
    
    let decoded = base64url_decode(user_id)?;
    if decoded.len() > 64 {
        return Err(WebAuthnError::Validation("User ID too long (maximum 64 bytes)".to_string()));
    }
    
    Ok(())
}

/// Validate origin against allowed origins
pub fn validate_origin(origin: &str, allowed_origins: &[String]) -> Result<(), WebAuthnError> {
    if !allowed_origins.contains(&origin.to_string()) {
        return Err(WebAuthnError::Validation(format!("Invalid origin: {}", origin)));
    }
    Ok(())
}

/// Validate RP ID against origin
pub fn validate_rp_id(rp_id: &str, origin: &str) -> Result<(), WebAuthnError> {
    let origin_url = url::Url::parse(origin)
        .map_err(|_| WebAuthnError::Validation("Invalid origin URL".to_string()))?;
    
    if let Some(host) = origin_url.host_str() {
        if host == rp_id || host.ends_with(&format!(".{}", rp_id)) {
            Ok(())
        } else {
            Err(WebAuthnError::Validation("RP ID does not match origin".to_string()))
        }
    } else {
        Err(WebAuthnError::Validation("No host in origin".to_string()))
    }
}

/// Get supported cryptographic algorithms for FIDO compliance
pub fn get_supported_algorithms() -> Vec<(String, i32)> {
    vec![
        // Required algorithms for FIDO compliance
        ("public-key".to_string(), -7),   // ES256 (ECDSA with SHA-256)
        ("public-key".to_string(), -257), // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
        ("public-key".to_string(), -8),   // Ed25519
        ("public-key".to_string(), -65535), // RS1 (RSASSA-PKCS1-v1_5 with SHA-1)
        ("public-key".to_string(), -35),  // ES384 (ECDSA with SHA-384) 
        ("public-key".to_string(), -36),  // ES512 (ECDSA with SHA-512)
        ("public-key".to_string(), -37),  // PS256 (RSASSA-PSS with SHA-256)
        ("public-key".to_string(), -38),  // PS384 (RSASSA-PSS with SHA-384)
        ("public-key".to_string(), -39),  // PS512 (RSASSA-PSS with SHA-512)
        ("public-key".to_string(), -258), // RS384 (RSASSA-PKCS1-v1_5 with SHA-384)
        ("public-key".to_string(), -259), // RS512 (RSASSA-PKCS1-v1_5 with SHA-512)
    ]
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
        assert!(validate_challenge(&challenge1).is_ok());
        assert!(validate_challenge(&challenge2).is_ok());
    }

    #[test]
    fn test_base64url_encode_decode() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_validate_challenge() {
        let valid_challenge = generate_challenge();
        assert!(validate_challenge(&valid_challenge).is_ok());
        
        // Too short
        assert!(validate_challenge("dGVzdA").is_err());
        
        // Invalid base64url
        assert!(validate_challenge("invalid+/=").is_err());
    }

    #[test]
    fn test_validate_user_id() {
        let valid_user_id = generate_user_id();
        assert!(validate_user_id(&valid_user_id).is_ok());
        
        // Empty
        assert!(validate_user_id("").is_err());
        
        // Invalid base64url
        assert!(validate_user_id("invalid+/=").is_err());
    }

    #[test]
    fn test_validate_origin() {
        let allowed_origins = vec!["https://example.com".to_string()];
        
        assert!(validate_origin("https://example.com", &allowed_origins).is_ok());
        assert!(validate_origin("https://malicious.com", &allowed_origins).is_err());
    }

    #[test]
    fn test_validate_rp_id() {
        assert!(validate_rp_id("example.com", "https://example.com").is_ok());
        assert!(validate_rp_id("example.com", "https://sub.example.com").is_ok());
        assert!(validate_rp_id("malicious.com", "https://example.com").is_err());
    }
}