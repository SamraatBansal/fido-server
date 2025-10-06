//! Cryptographic utilities

use std::time::Duration;
use uuid::Uuid;
use jsonwebtoken::{encode, EncodingKey, Header, decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{AppError, Result};

/// JWT claims for session tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub iat: usize,  // Issued at
    pub exp: usize,  // Expiration
    pub auth_type: String, // Authentication type
}

/// JWT manager for secure token generation and validation
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtManager {
    /// Create a new JWT manager with the given secret
    pub fn new(secret: &[u8]) -> Result<Self> {
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);
        
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_iat = true;

        Ok(Self {
            encoding_key,
            decoding_key,
            validation,
        })
    }

    /// Generate a session token
    pub fn generate_session_token(
        &self,
        user_id: &Uuid,
        duration: Duration,
        auth_type: &str,
    ) -> Result<String> {
        let now = chrono::Utc::now();
        let iat = now.timestamp() as usize;
        let exp = (now + chrono::Duration::from_std(duration).unwrap()).timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            iat,
            exp,
            auth_type: auth_type.to_string(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::InvalidToken(format!("Token generation failed: {}", e)))?;

        Ok(token)
    }

    /// Validate and decode a session token
    pub fn validate_session_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| AppError::InvalidToken(format!("Token validation failed: {}", e)))?;

        Ok(token_data.claims)
    }
}

/// Simple encryption utility for sensitive data
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
        self.rng.fill(&mut nonce_bytes)
            .map_err(|e| AppError::InvalidEncryption(format!("Failed to generate nonce: {}", e)))?;
        
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = plaintext.to_vec();
        
        self.key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|e| AppError::InvalidEncryption(format!("Encryption failed: {}", e)))?;
        
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
        
        self.key.open_in_place(nonce, Aad::empty(), &mut plaintext)
            .map_err(|e| AppError::InvalidEncryption(format!("Decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
}