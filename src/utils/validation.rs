//! Validation utilities

use lazy_static::lazy_static;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

lazy_static! {
    /// Username validation regex - alphanumeric + @._+-
    pub static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9@._+-]+$").unwrap();
}

/// Validate RP ID according to FIDO2 specification
pub fn validate_rp_id(rp_id: &str) -> bool {
    // Basic validation - should be a valid domain
    !rp_id.is_empty() && rp_id.contains('.') && rp_id.len() <= 255
}

/// Validate origin according to WebAuthn specification
pub fn validate_origin(origin: &str, rp_id: &str) -> bool {
    // Check if origin matches RP ID
    origin.contains(rp_id) && origin.starts_with("https://")
}

/// Check if attestation format is supported
pub fn supports_attestation_format(format: &str) -> bool {
    matches!(format, "packed" | "fido-u2f" | "none" | "android-key" | "android-safetynet")
}

/// Check if cipher suite is strong
pub fn is_strong_cipher_suite(cipher: &str) -> bool {
    // List of strong cipher suites
    matches!(cipher, 
        "TLS_AES_256_GCM_SHA384" | 
        "TLS_CHACHA20_POLY1305_SHA256" | 
        "TLS_AES_128_GCM_SHA256"
    )
}

/// Validate challenge according to FIDO2 specification
pub fn validate_challenge(challenge: &str) -> bool {
    // Challenge must be base64url-encoded and at least 16 bytes when decoded
    if challenge.is_empty() {
        return false;
    }
    
    // Try to decode as base64url
    match URL_SAFE_NO_PAD.decode(challenge) {
        Ok(decoded) => decoded.len() >= 16,
        Err(_) => false,
    }
}

/// Validate credential ID according to WebAuthn specification
pub fn validate_credential_id(credential_id: &str) -> bool {
    // Credential ID must be base64url-encoded
    if credential_id.is_empty() || credential_id.len() > 1024 {
        return false;
    }
    
    URL_SAFE_NO_PAD.decode(credential_id).is_ok()
}

/// Validate user verification requirement
pub fn validate_user_verification(uv: &str) -> bool {
    matches!(uv, "required" | "preferred" | "discouraged")
}

/// Validate attestation conveyance preference
pub fn validate_attestation_conveyance(attestation: &str) -> bool {
    matches!(attestation, "none" | "indirect" | "direct" | "enterprise")
}

/// Check if algorithm is supported
pub fn is_supported_algorithm(alg: i64) -> bool {
    // Supported COSE algorithms
    matches!(alg, -7 | -257 | -35 | -36 | -258 | -259 | -37 | -38 | -39)
}

/// Validate authenticator attachment
pub fn validate_authenticator_attachment(attachment: &str) -> bool {
    matches!(attachment, "platform" | "cross-platform" | "null")
}

/// Validate resident key requirement
pub fn validate_resident_key_requirement(requirement: &str) -> bool {
    matches!(requirement, "required" | "preferred" | "discouraged")
}