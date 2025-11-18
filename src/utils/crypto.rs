//! Cryptographic utilities

use rand::RngCore;
use crate::{AppError, Result};

/// Generate a cryptographically secure random challenge
pub fn generate_challenge(size: usize) -> Result<Vec<u8>> {
    let mut challenge = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut challenge);
    Ok(challenge)
}