use crate::error::{AppError, Result};
use rand::Rng;

pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.gen()).collect()
}

pub fn base64_url_encode(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

pub fn base64_url_decode(data: &str) -> Result<Vec<u8>> {
    base64::decode_config(data, base64::URL_SAFE_NO_PAD)
        .map_err(|_| AppError::validation("Invalid base64url encoding"))
}

pub fn generate_challenge() -> String {
    let challenge_bytes = generate_random_bytes(32);
    base64_url_encode(&challenge_bytes)
}

pub fn validate_base64_url(data: &str) -> Result<()> {
    base64_url_decode(data)?;
    Ok(())
}