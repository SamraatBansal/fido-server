//! Utility functions

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

pub fn base64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64.decode(data)
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}