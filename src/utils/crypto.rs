//! Cryptographic utilities for secure operations
//! 
//! This module provides encryption, JWT token management, and other
//! cryptographic utilities needed for secure WebAuthn operations.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonRng, PasswordHash, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    decode, encode, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
    pub iss: String,        // Issuer
    pub aud: String,        // Audience
    pub jti: String,        // JWT ID
    pub session_type: String, // Session type
}

/// JWT token manager
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    issuer: String,
    audience: String,
}

impl JwtManager {
    /// Create a new JWT manager with the provided secret
    pub fn new(secret: &[u8], issuer: String, audience: String) -> Result<Self> {
        if secret.len() < 32 {
            return Err(AppError::Configuration(
                "JWT secret must be at least 32 bytes".to_string(),
            ));
        }

        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_issuer(&[&issuer]);
        validation.set_audience(&[&audience]);
        validation.validate_exp = true;
        validation.validate_iat = true;

        Ok(Self {
            encoding_key,
            decoding_key,
            validation,
            issuer,
            audience,
        })
    }

    /// Generate a session token for the user
    pub fn generate_session_token(
        &self,
        user_id: &Uuid,
        expires_in: Duration,
        session_type: &str,
    ) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("System time error: {}", e)))?;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (now.as_secs() + expires_in.as_secs()) as usize,
            iat: now.as_secs() as usize,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            jti: Uuid::new_v4().to_string(),
            session_type: session_type.to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("JWT encoding failed: {}", e)))
    }

    /// Validate and decode a session token
    pub fn validate_session_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| AppError::AuthorizationFailed(format!("Invalid token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Refresh an existing token
    pub fn refresh_token(&self, token: &str, expires_in: Duration) -> Result<String> {
        let claims = self.validate_session_token(token)?;
        
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid user ID in token: {}", e)))?;

        self.generate_session_token(&user_id, expires_in, &claims.session_type)
    }
}

/// Credential encryption utilities
pub struct CredentialEncryption {
    key: Key<Aes256Gcm>,
}

impl CredentialEncryption {
    /// Create a new encryption instance with the provided key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: Key::<Aes256Gcm>::from_slice(key),
        }
    }

    /// Encrypt sensitive credential data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let mut ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| AppError::Internal(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);

        Ok(result)
    }

    /// Decrypt sensitive credential data
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(AppError::InvalidRequest("Invalid ciphertext format".to_string()));
        }

        let cipher = Aes256Gcm::new(&self.key);
        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| AppError::Internal(format!("Decryption failed: {}", e)))
    }
}

/// Password hashing utilities
pub struct PasswordHasher {
    argon2: Argon2,
}

impl PasswordHasher {
    /// Create a new password hasher with default configuration
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut ArgonRng);
        
        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))
            .map(|hash| hash.to_string())
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid password hash: {}", e)))?;

        Ok(self.argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure random utilities
pub struct SecureRandom;

impl SecureRandom {
    /// Generate a secure random string of specified length
    pub fn generate_string(length: usize) -> Result<String> {
        use rand::{distributions::Alphanumeric, Rng};
        
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();

        Ok(s)
    }

    /// Generate secure random bytes
    pub fn generate_bytes(length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut bytes);
        Ok(bytes)
    }

    /// Generate a secure random 32-byte key
    pub fn generate_key() -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }
}

/// API key utilities for service-to-service authentication
pub struct ApiKeyManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new(secret: &[u8]) -> Result<Self> {
        if secret.len() < 32 {
            return Err(AppError::Configuration(
                "API key secret must be at least 32 bytes".to_string(),
            ));
        }

        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        Ok(Self {
            encoding_key,
            decoding_key,
        })
    }

    /// Generate a new API key
    pub fn generate_api_key(&self, service_id: &str, expires_in: Duration) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("System time error: {}", e)))?;

        let claims = serde_json::json!({
            "sub": service_id,
            "exp": now.as_secs() + expires_in.as_secs(),
            "iat": now.as_secs(),
            "type": "api_key"
        });

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("API key generation failed: {}", e)))
    }

    /// Validate an API key
    pub fn validate_api_key(&self, api_key: &str) -> Result<String> {
        let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        let token_data = decode::<serde_json::Value>(api_key, &self.decoding_key, &validation)
            .map_err(|e| AppError::AuthorizationFailed(format!("Invalid API key: {}", e)))?;

        let claims = token_data.claims;
        
        claims
            .get("type")
            .and_then(|v| v.as_str())
            .filter(|&t| t == "api_key")
            .ok_or_else(|| AppError::AuthorizationFailed("Invalid API key type".to_string()))?;

        claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| AppError::AuthorizationFailed("Invalid API key subject".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_manager() {
        let secret = b"this_is_a_very_secure_secret_key_for_jwt_testing_32bytes";
        let jwt_manager = JwtManager::new(
            secret,
            "fido-server".to_string(),
            "fido-client".to_string(),
        ).unwrap();

        let user_id = Uuid::new_v4();
        let token = jwt_manager
            .generate_session_token(&user_id, Duration::from_secs(3600), "webauthn")
            .unwrap();

        let claims = jwt_manager.validate_session_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.session_type, "webauthn");
    }

    #[test]
    fn test_credential_encryption() {
        let key = [0u8; 32];
        let encryption = CredentialEncryption::new(&key);
        
        let plaintext = b"sensitive credential data";
        let encrypted = encryption.encrypt(plaintext).unwrap();
        
        assert_ne!(encrypted, plaintext.to_vec());
        assert!(encrypted.len() > plaintext.len());
        
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_password_hasher() {
        let hasher = PasswordHasher::new();
        let password = "secure_password_123";
        
        let hash = hasher.hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2"));
        
        assert!(hasher.verify_password(password, &hash).unwrap());
        assert!(!hasher.verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_secure_random() {
        let random_string = SecureRandom::generate_string(32).unwrap();
        assert_eq!(random_string.len(), 32);
        
        let random_bytes = SecureRandom::generate_bytes(16).unwrap();
        assert_eq!(random_bytes.len(), 16);
        
        let key = SecureRandom::generate_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_api_key_manager() {
        let secret = b"this_is_a_very_secure_secret_key_for_api_keys_32bytes";
        let api_key_manager = ApiKeyManager::new(secret).unwrap();
        
        let api_key = api_key_manager
            .generate_api_key("test-service", Duration::from_secs(3600))
            .unwrap();
        
        let service_id = api_key_manager.validate_api_key(&api_key).unwrap();
        assert_eq!(service_id, "test-service");
    }
}