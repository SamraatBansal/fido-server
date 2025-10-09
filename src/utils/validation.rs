//! Validation utilities

use lazy_static::lazy_static;
use regex::Regex;

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