use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

pub fn generate_challenge() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_data(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

pub fn verify_hash(data: &[u8], hash: &str) -> bool {
    let computed_hash = hash_data(data);
    computed_hash == hash
}

pub fn generate_session_token() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}