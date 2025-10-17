//! Cryptographic service for security operations

use crate::error::{AppError, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

#[async_trait]
pub trait CryptoService: Send + Sync {
    async fn generate_secure_random(&self, length: usize) -> Result<Vec<u8>>;
    async fn hash_data(&self, data: &[u8]) -> Result<String>;
    async fn verify_hash(&self, data: &[u8], hash: &str) -> Result<bool>;
}

pub struct CryptoServiceImpl;

impl CryptoServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CryptoService for CryptoServiceImpl {
    async fn generate_secure_random(&self, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        getrandom::getrandom(&mut bytes).map_err(|e| AppError::CryptoError(e.to_string()))?;
        Ok(bytes)
    }

    async fn hash_data(&self, data: &[u8]) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    async fn verify_hash(&self, data: &[u8], hash: &str) -> Result<bool> {
        let computed_hash = self.hash_data(data).await?;
        Ok(computed_hash == hash)
    }
}