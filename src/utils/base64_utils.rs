//! Base64 encoding/decoding utilities

use base64::{Engine as _, engine::general_purpose};

/// Encode bytes to base64url string
pub fn encode_base64url(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url string to bytes
pub fn decode_base64url(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(data)
}