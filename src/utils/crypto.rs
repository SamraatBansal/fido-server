//! Cryptographic utilities for secure operations
//! 
//! This module provides JWT token management, encryption utilities,
//! and other cryptographic functions needed for secure WebAuthn operations.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{AppError, Result};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub iat: usize,         // Issued at
    pub exp: usize,         // Expiration
    pub iss: String,        // Issuer
    pub aud: String,        // Audience
    pub auth_method: String, // Authentication method
    pub jti: String,        // JWT ID
}

/// JWT manager for secure token generation and validation
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
    rng: SystemRandom,
}

impl JwtManager {
    /// Create a new JWT manager with the given secret
    pub fn new(secret: &[u8], issuer: String, audience: String) -> Result<Self> {
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
            audience,
            rng: SystemRandom::new(),
        })
    }

    /// Generate a session token for a user
    pub fn generate_session_token(
        &self,
        user_id: &Uuid,
        duration: Duration,
        auth_method: &str,
    ) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("Time error: {}", e)))?;

        let iat = now.as_secs() as usize;
        let exp = (now + duration).as_secs() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            iat,
            exp,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            auth_method: auth_method.to_string(),
            jti: self.generate_jti()?,
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("JWT encoding error: {}", e)))?;

        Ok(token)
    }

    /// Validate and decode a session token
    pub fn validate_session_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AppError::InvalidToken(format!("JWT validation error: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Generate a secure JWT ID
    fn generate_jti(&self) -> Result<String> {
        let mut bytes = [0u8; 16];
        self.rng
            .fill(&mut bytes)
            .map_err(|e| AppError::Internal(format!("Failed to generate JTI: {}", e)))?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
}

/// Encryption utilities for sensitive data
pub struct EncryptionManager {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl EncryptionManager {
    /// Create a new encryption manager with the given key
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .expect("Invalid key length for AES-256-GCM");
        let key = LessSafeKey::new(unbound_key);

        Self {
            key,
            rng: SystemRandom::new(),
        }
    }

    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|e| AppError::Internal(format!("Failed to generate nonce: {}", e)))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        
        let mut ciphertext = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|e| AppError::Internal(format!("Encryption error: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(AppError::InvalidEncryption("Invalid ciphertext length".to_string()));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes.try_into()
                .map_err(|_| AppError::InvalidEncryption("Invalid nonce length".to_string()))?
        );

        let mut plaintext = encrypted_data.to_vec();
        self.key
            .open_in_place(nonce, Aad::empty(), &mut plaintext)
            .map_err(|e| AppError::InvalidEncryption(format!("Decryption error: {}", e)))?;

        Ok(plaintext)
    }
}

/// Secure random number generator utilities
pub struct SecureRandomGenerator {
    rng: SystemRandom,
}

impl SecureRandomGenerator {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate random bytes
    pub fn generate_bytes(&self, len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        self.rng
            .fill(&mut bytes)
            .map_err(|e| AppError::Internal(format!("Failed to generate random bytes: {}", e)))?;

        Ok(bytes)
    }

    /// Generate a random challenge for WebAuthn
    pub fn generate_challenge(&self) -> Result<String> {
        let bytes = self.generate_bytes(32)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Generate a secure session ID
    pub fn generate_session_id(&self) -> Result<String> {
        let bytes = self.generate_bytes(32)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
}

/// Password hashing utilities (for user management)
pub struct PasswordManager {
    cost: u32,
}

impl PasswordManager {
    pub fn new(cost: u32) -> Self {
        Self { cost }
    }

    /// Hash a password
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = rand::random::<[u8; 32]>();
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 65536,
            time_cost: 3,
            lanes: 4,
            thread_mode: argon2::ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 32,
            salt,
        };

        let hash = argon2::hash_raw(password.as_bytes(), &config.salt, &config)
            .map_err(|e| AppError::Internal(format!("Password hashing error: {}", e)))?;

        // Combine salt and hash for storage
        let mut result = config.salt.to_vec();
        result.extend_from_slice(&hash);

        Ok(base64::engine::general_purpose::STANDARD.encode(result))
    }

    /// Verify a password
    pub fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool> {
        let data = base64::engine::general_purpose::STANDARD
            .decode(stored_hash)
            .map_err(|_| AppError::InvalidPassword("Invalid hash format".to_string()))?;

        if data.len() != 64 { // 32 bytes salt + 32 bytes hash
            return Err(AppError::InvalidPassword("Invalid hash length".to_string()));
        }

        let (salt, stored_hash_bytes) = data.split_at(32);

        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 65536,
            time_cost: 3,
            lanes: 4,
            thread_mode: argon2::ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 32,
            salt: salt.try_into()
                .map_err(|_| AppError::InvalidPassword("Invalid salt length".to_string()))?,
        };

        let hash = argon2::hash_raw(password.as_bytes(), &config.salt, &config)
            .map_err(|e| AppError::Internal(format!("Password hashing error: {}", e)))?;

        Ok(hash == stored_hash_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_token_generation_and_validation() {
        let secret = b"test_secret_key_that_is_long_enough_for_hs256";
        let jwt_manager = JwtManager::new(
            secret,
            "test_issuer".to_string(),
            "test_audience".to_string(),
        ).unwrap();

        let user_id = Uuid::new_v4();
        let token = jwt_manager
            .generate_session_token(&user_id, Duration::from_secs(3600), "webauthn")
            .unwrap();

        let claims = jwt_manager.validate_session_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.auth_method, "webauthn");
        assert_eq!(claims.iss, "test_issuer");
        assert_eq!(claims.aud, "test_audience");
    }

    #[test]
    fn test_encryption_decryption() {
        let key = [0u8; 32]; // In production, use a proper key
        let encryption_manager = EncryptionManager::new(&key);

        let plaintext = b"Hello, World!";
        let ciphertext = encryption_manager.encrypt(plaintext).unwrap();
        let decrypted = encryption_manager.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_secure_random_generation() {
        let rng = SecureRandomGenerator::new();
        
        let bytes1 = rng.generate_bytes(32).unwrap();
        let bytes2 = rng.generate_bytes(32).unwrap();
        
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
    }

    #[test]
    fn test_password_hashing() {
        let password_manager = PasswordManager::new(12);
        let password = "test_password_123";

        let hash = password_manager.hash_password(password).unwrap();
        let is_valid = password_manager.verify_password(password, &hash).unwrap();

        assert!(is_valid);
        
        // Test wrong password
        let is_invalid = password_manager.verify_password("wrong_password", &hash).unwrap();
        assert!(!is_invalid);
    }
}