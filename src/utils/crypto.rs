//! Cryptographic utilities

use rand::RngCore;

/// Generate secure random bytes
pub fn generate_secure_random(len: usize) -> crate::error::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Generate secure random string
pub fn generate_secure_random_string(len: usize) -> Result<String> {
    use base64::{Engine as _, engine::general_purpose};
    let bytes = generate_secure_random(len)?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(&bytes[..len]))
}

/// Hash password using PBKDF2
pub fn hash_password(password: &str, salt: &[u8]) -> Result<String> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use base64::{Engine as _, engine::general_purpose};
    
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut hash);
    
    Ok(general_purpose::STANDARD.encode(&hash))
}

/// Verify password hash
pub fn verify_password(password: &str, salt: &[u8], hash: &str) -> Result<bool> {
    let computed_hash = hash_password(password, salt)?;
    Ok(computed_hash == hash)
}