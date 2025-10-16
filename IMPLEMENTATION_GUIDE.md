# FIDO2/WebAuthn Server - Implementation Guide

## Overview

This implementation guide provides concrete code examples, patterns, and best practices for building a secure, compliant FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library.

## 1. Project Setup and Configuration

### 1.1 Core Dependencies

```toml
# Cargo.toml additions for enhanced security and testing
[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"
actix-identity = "0.7"
actix-session = { version = "0.9", features = ["cookie-session"] }

# FIDO/WebAuthn
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"

# Security
ring = "0.17"
subtle = "2.5"
zeroize = "1.7"

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid", "serde_json"] }
diesel_migrations = "2.1"
r2d2 = "0.8"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Async
tokio = { version = "1.40", features = ["full"] }
futures = "0.3"

# Cryptography
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }
rand = "0.8"
sha2 = "0.10"
hmac = "0.12"

# Configuration
config = "0.14"
dotenv = "0.15"

# Logging
log = "0.4"
env_logger = "0.11"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error Handling
thiserror = "1.0"
anyhow = "1.0"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Validation
validator = { version = "0.18", features = ["derive"] }
regex = "1.10"

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tempfile = "3.8"
wiremock = "0.6"
proptest = "1.4"
criterion = { version = "0.5", features = ["html_reports"] }
tokio-test = "0.4"
pretty_assertions = "1.4"
```

### 1.2 Configuration Structure

```rust
// src/config/mod.rs
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub keep_alive: Duration,
    pub client_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub challenge_timeout: Duration,
    pub attestation_preference: String,
    pub user_verification: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub session_timeout: Duration,
    pub max_login_attempts: u32,
    pub rate_limit_window: Duration,
    pub rate_limit_max: u32,
    pub csrf_token_length: usize,
    pub bcrypt_cost: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut settings = config::Config::builder();
        
        // Load default configuration
        settings = settings.add_source(config::File::with_name("config/default"));
        
        // Load environment-specific configuration
        let env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".into());
        settings = settings.add_source(config::File::with_name(&format!("config/{}", env)).required(false));
        
        // Load environment variables
        settings = settings.add_source(config::Environment::with_prefix("APP"));
        
        let config = settings.build()?;
        
        config.try_deserialize()
    }
}
```

## 2. WebAuthn Service Implementation

### 2.1 Core WebAuthn Service

```rust
// src/services/webauthn.rs
use crate::config::WebAuthnConfig;
use crate::error::{WebAuthnError, WebAuthnResult};
use crate::models::{Challenge, User, Credential};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use rand::{thread_rng, RngCore};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

pub struct WebAuthnService {
    webauthn: Webauthn,
    config: WebAuthnConfig,
    challenges: HashMap<String, Challenge>,
}

impl WebAuthnService {
    pub fn new(config: WebAuthnConfig) -> WebAuthnResult<Self> {
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|e| WebAuthnError::Configuration(e.to_string()))?
            .build()
            .map_err(|e| WebAuthnError::Configuration(e.to_string()))?;

        Ok(Self {
            webauthn,
            config,
            challenges: HashMap::new(),
        })
    }

    pub async fn generate_registration_challenge(
        &mut self,
        user: &User,
    ) -> WebAuthnResult<RegistrationChallengeResponse> {
        // Generate unique challenge
        let challenge_bytes = self.generate_secure_challenge();
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        
        // Create user handle
        let user_handle = user.id.as_bytes().to_vec();
        
        // Build credential creation options
        let ccro = self.webauthn
            .generate_challenge_register_options(
                &user.username,
                &user.display_name,
                &user_handle,
                Some(self.config.attestation_preference.as_str()),
                Some(self.config.user_verification.as_str()),
                None,
                None,
            )
            .map_err(|e| WebAuthnError::ChallengeGeneration(e.to_string()))?;

        // Store challenge
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: challenge_bytes.clone(),
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.config.challenge_timeout.num_seconds() as i64),
            created_at: Utc::now(),
            used: false,
            metadata: Some(serde_json::json!({
                "user_id": user.id,
                "username": user.username
            })),
        };

        self.challenges.insert(challenge_b64.clone(), challenge);

        // Convert to response format
        let response = RegistrationChallengeResponse {
            status: "ok".to_string(),
            challenge: challenge_b64,
            rp: RpInfo {
                name: self.config.rp_name.clone(),
                id: self.config.rp_id.clone(),
            },
            user: UserInfo {
                id: general_purpose::URL_SAFE_NO_PAD.encode(&user_handle),
                name: user.username.clone(),
                display_name: user.display_name.clone(),
            },
            pub_key_cred_params: ccro.pub_key_cred_params,
            timeout: self.config.challenge_timeout.num_milliseconds() as u64,
            attestation: self.config.attestation_preference.clone(),
            authenticator_selection: ccro.authenticator_selection,
        };

        Ok(response)
    }

    pub async fn verify_registration(
        &mut self,
        registration_response: RegistrationResponse,
        challenge_b64: &str,
    ) -> WebAuthnResult<CredentialRegistrationResult> {
        // Retrieve and validate challenge
        let challenge = self.challenges.get(challenge_b64)
            .ok_or_else(|| WebAuthnError::InvalidChallenge("Challenge not found".to_string()))?;

        if challenge.used {
            return Err(WebAuthnError::InvalidChallenge("Challenge already used".to_string()));
        }

        if Utc::now() > challenge.expires_at {
            return Err(WebAuthnError::InvalidChallenge("Challenge expired".to_string()));
        }

        // Convert registration response
        let reg_credential = self.convert_registration_response(registration_response)?;

        // Verify registration
        let result = self.webauthn
            .register_credential(
                &reg_credential,
                &challenge.challenge,
            )
            .map_err(|e| WebAuthnError::AttestationVerification(e.to_string()))?;

        // Mark challenge as used
        if let Some(challenge) = self.challenges.get_mut(challenge_b64) {
            challenge.used = true;
        }

        // Create credential registration result
        let credential_result = CredentialRegistrationResult {
            status: "ok".to_string(),
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&result.cred_id),
            user_verified: result.user_verified,
            attestation_type: result.attestation_type.to_string(),
            aaguid: result.aaguid.map(|aaguid| general_purpose::URL_SAFE_NO_PAD.encode(&aaguid)),
        };

        Ok(credential_result)
    }

    pub async fn generate_authentication_challenge(
        &mut self,
        user: &User,
        credentials: &[Credential],
    ) -> WebAuthnResult<AuthenticationChallengeResponse> {
        // Generate unique challenge
        let challenge_bytes = self.generate_secure_challenge();
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);

        // Convert credentials to allow credentials format
        let allow_credentials: Vec<_> = credentials
            .iter()
            .map(|cred| AllowCredentials {
                type_: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: cred.transports.clone(),
            })
            .collect();

        // Store challenge
        let challenge = Challenge {
            id: Uuid::new_v4(),
            challenge: challenge_bytes.clone(),
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.config.challenge_timeout.num_seconds() as i64),
            created_at: Utc::now(),
            used: false,
            metadata: Some(serde_json::json!({
                "user_id": user.id,
                "username": user.username,
                "allowed_credentials": allow_credentials.iter().map(|c| &c.id).collect::<Vec<_>>()
            })),
        };

        self.challenges.insert(challenge_b64.clone(), challenge);

        // Create response
        let response = AuthenticationChallengeResponse {
            status: "ok".to_string(),
            challenge: challenge_b64,
            allow_credentials: allow_credentials,
            user_verification: self.config.user_verification.clone(),
            timeout: self.config.challenge_timeout.num_milliseconds() as u64,
            rp_id: self.config.rp_id.clone(),
        };

        Ok(response)
    }

    pub async fn verify_authentication(
        &mut self,
        auth_response: AuthenticationResponse,
        challenge_b64: &str,
        stored_credential: &Credential,
    ) -> WebAuthnResult<AuthenticationResult> {
        // Retrieve and validate challenge
        let challenge = self.challenges.get(challenge_b64)
            .ok_or_else(|| WebAuthnError::InvalidChallenge("Challenge not found".to_string()))?;

        if challenge.used {
            return Err(WebAuthnError::InvalidChallenge("Challenge already used".to_string()));
        }

        if Utc::now() > challenge.expires_at {
            return Err(WebAuthnError::InvalidChallenge("Challenge expired".to_string()));
        }

        // Convert authentication response
        let auth_credential = self.convert_authentication_response(auth_response)?;

        // Create stored credential data
        let stored_cred = StoredCredential {
            cred_id: stored_credential.credential_id.clone(),
            cred: stored_credential.credential_public_key.clone(),
            counter: stored_credential.sign_count,
            user_verified: stored_credential.user_verification == "required",
            registration_policy: UserVerificationPolicy::Required,
        };

        // Verify authentication
        let result = self.webauthn
            .authenticate_credential(
                &auth_credential,
                &stored_cred,
                &challenge.challenge,
            )
            .map_err(|e| WebAuthnError::AssertionVerification(e.to_string()))?;

        // Mark challenge as used
        if let Some(challenge) = self.challenges.get_mut(challenge_b64) {
            challenge.used = true;
        }

        // Create authentication result
        let auth_result = AuthenticationResult {
            status: "ok".to_string(),
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&result.cred_id),
            user_verified: result.user_verified,
            counter: result.counter,
            session_token: self.generate_session_token(),
        };

        Ok(auth_result)
    }

    fn generate_secure_challenge(&self) -> Vec<u8> {
        let mut challenge = vec![0u8; 32];
        thread_rng().fill_bytes(&mut challenge);
        challenge
    }

    fn generate_session_token(&self) -> String {
        let mut token = vec![0u8; 32];
        thread_rng().fill_bytes(&mut token);
        general_purpose::URL_SAFE_NO_PAD.encode(&token)
    }

    fn convert_registration_response(
        &self,
        response: RegistrationResponse,
    ) -> WebAuthnResult<RegisterPublicKeyCredential> {
        // Implementation for converting API response to webauthn-rs format
        // This would involve base64 decoding and struct conversion
        todo!("Implement registration response conversion")
    }

    fn convert_authentication_response(
        &self,
        response: AuthenticationResponse,
    ) -> WebAuthnResult<PublicKeyCredential> {
        // Implementation for converting API response to webauthn-rs format
        // This would involve base64 decoding and struct conversion
        todo!("Implement authentication response conversion")
    }

    pub fn cleanup_expired_challenges(&mut self) {
        let now = Utc::now();
        self.challenges.retain(|_, challenge| challenge.expires_at > now);
    }
}

// Response structures
#[derive(Debug, Serialize)]
pub struct RegistrationChallengeResponse {
    pub status: String,
    pub challenge: String,
    pub rp: RpInfo,
    pub user: UserInfo,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u64,
    pub attestation: String,
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

#[derive(Debug, Serialize)]
pub struct RpInfo {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct CredentialRegistrationResult {
    pub status: String,
    pub credential_id: String,
    pub user_verified: bool,
    pub attestation_type: String,
    pub aaguid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationChallengeResponse {
    pub status: String,
    pub challenge: String,
    pub allow_credentials: Vec<AllowCredentials>,
    pub user_verification: String,
    pub timeout: u64,
    pub rp_id: String,
}

#[derive(Debug, Serialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationResult {
    pub status: String,
    pub credential_id: String,
    pub user_verified: bool,
    pub counter: u32,
    pub session_token: String,
}

// Request structures
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    pub credential: PublicKeyCredential,
    pub session_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub credential: PublicKeyCredential,
    pub session_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AuthenticatorResponse,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticatorResponse {
    pub attestation_object: Option<String>,
    pub client_data_json: String,
    pub authenticator_data: Option<String>,
    pub signature: Option<String>,
    pub user_handle: Option<String>,
}
```

### 2.2 Credential Service

```rust
// src/services/credential.rs
use crate::db::repositories::CredentialRepository;
use crate::error::{CredentialError, CredentialResult};
use crate::models::{Credential, User};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use diesel::PgConnection;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;
use uuid::Uuid;

pub struct CredentialService {
    repository: Arc<CredentialRepository>,
    encryption_key: LessSafeKey,
    rng: SystemRandom,
}

impl CredentialService {
    pub fn new(repository: Arc<CredentialRepository>, encryption_key: &[u8]) -> CredentialResult<Self> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, encryption_key)
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;
        let encryption_key = LessSafeKey::new(unbound_key);

        Ok(Self {
            repository,
            encryption_key,
            rng: SystemRandom::new(),
        })
    }

    pub async fn create_credential(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        attestation_type: &str,
        aaguid: Option<&[u8]>,
    ) -> CredentialResult<Credential> {
        // Check for duplicate credential
        if self.repository.credential_exists(conn, credential_id)? {
            return Err(CredentialError::DuplicateCredential("Credential already exists".to_string()));
        }

        // Encrypt public key
        let encrypted_public_key = self.encrypt_data(public_key)?;

        // Create credential
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id,
            credential_id: credential_id.to_vec(),
            credential_public_key: encrypted_public_key,
            attestation_type: attestation_type.to_string(),
            aaguid: aaguid.map(|aaguid| aaguid.to_vec()),
            sign_count: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used: None,
            is_active: true,
            backup_eligible: false,
            backup_state: false,
            transports: Some(serde_json::json!(["usb", "nfc", "ble", "internal"])),
            user_verification: "preferred".to_string(),
        };

        let created_credential = self.repository.create_credential(conn, credential)?;
        Ok(created_credential)
    }

    pub async fn get_credential(
        &self,
        conn: &mut PgConnection,
        credential_id: &[u8],
    ) -> CredentialResult<Option<Credential>> {
        let credential = self.repository.get_credential(conn, credential_id)?;
        
        if let Some(mut cred) = credential {
            // Decrypt public key
            cred.credential_public_key = self.decrypt_data(&cred.credential_public_key)?;
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    pub async fn get_user_credentials(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> CredentialResult<Vec<Credential>> {
        let credentials = self.repository.get_user_credentials(conn, user_id)?;
        
        // Decrypt public keys
        let mut decrypted_credentials = Vec::new();
        for mut cred in credentials {
            cred.credential_public_key = self.decrypt_data(&cred.credential_public_key)?;
            decrypted_credentials.push(cred);
        }

        Ok(decrypted_credentials)
    }

    pub async fn update_credential_counter(
        &self,
        conn: &mut PgConnection,
        credential_id: &[u8],
        new_counter: u64,
    ) -> CredentialResult<()> {
        // Validate counter is greater than stored value
        let stored_credential = self.repository.get_credential(conn, credential_id)?
            .ok_or_else(|| CredentialError::CredentialNotFound("Credential not found".to_string()))?;

        if new_counter <= stored_credential.sign_count {
            return Err(CredentialError::InvalidCounter("Counter regression detected".to_string()));
        }

        self.repository.update_credential_counter(conn, credential_id, new_counter)?;
        Ok(())
    }

    pub async fn revoke_credential(
        &self,
        conn: &mut PgConnection,
        credential_id: &[u8],
    ) -> CredentialResult<()> {
        self.repository.revoke_credential(conn, credential_id)?;
        Ok(())
    }

    pub async fn update_last_used(
        &self,
        conn: &mut PgConnection,
        credential_id: &[u8],
    ) -> CredentialResult<()> {
        self.repository.update_last_used(conn, credential_id, Utc::now())?;
        Ok(())
    }

    fn encrypt_data(&self, data: &[u8]) -> CredentialResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes)
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;
        
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::empty();

        let mut encrypted_data = data.to_vec();
        self.encryption_key.seal_in_place_append_tag(nonce, aad, &mut encrypted_data)
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        // Prepend nonce to encrypted data
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&encrypted_data);
        
        Ok(result)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> CredentialResult<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(CredentialError::EncryptionError("Invalid encrypted data".to_string()));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes.try_into()
                .map_err(|_| CredentialError::EncryptionError("Invalid nonce".to_string()))?
        );
        let aad = Aad::empty();

        let mut decrypted_data = ciphertext.to_vec();
        let decrypted_len = self.encryption_key.open_in_place(nonce, aad, &mut decrypted_data)
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        Ok(decrypted_data[..decrypted_len].to_vec())
    }
}
```

## 3. Database Implementation

### 3.1 Database Models

```rust
// src/db/models.rs
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::{users, credentials, challenges, sessions};

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub user_verification: String,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub user_verification: String,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub is_active: bool,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = sessions)]
pub struct NewSession {
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}
```

### 3.2 Database Schema

```sql
-- migrations/2023-01-01-000001_create_users_table.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);

-- migrations/2023-01-01-000002_create_credentials_table.sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    transports JSONB,
    user_verification VARCHAR(20) DEFAULT 'preferred'
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(is_active);
CREATE INDEX idx_credentials_user_active ON credentials(user_id, is_active);

-- migrations/2023-01-01-000003_create_challenges_table.sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used BOOLEAN DEFAULT false,
    metadata JSONB
);

CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_type ON challenges(challenge_type);
CREATE INDEX idx_challenges_used ON challenges(used);

-- migrations/2023-01-01-000004_create_sessions_table.sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    metadata JSONB
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_active ON sessions(is_active);

-- migrations/2023-01-01-000005_create_audit_log_table.sql
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
```

### 3.3 Repository Pattern Implementation

```rust
// src/db/repositories.rs
use crate::db::models::*;
use crate::error::{DatabaseError, DatabaseResult};
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use std::sync::Arc;
use uuid::Uuid;

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub struct UserRepository;

impl UserRepository {
    pub fn create_user(
        conn: &mut PgConnection,
        new_user: NewUser,
    ) -> DatabaseResult<User> {
        use crate::schema::users;

        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(conn)?;

        Ok(user)
    }

    pub fn get_user_by_id(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> DatabaseResult<Option<User>> {
        use crate::schema::users;

        let user = users::table
            .filter(users::id.eq(user_id))
            .first(conn)
            .optional()?;

        Ok(user)
    }

    pub fn get_user_by_username(
        conn: &mut PgConnection,
        username: &str,
    ) -> DatabaseResult<Option<User>> {
        use crate::schema::users;

        let user = users::table
            .filter(users::username.eq(username))
            .first(conn)
            .optional()?;

        Ok(user)
    }

    pub fn update_last_login(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> DatabaseResult<()> {
        use crate::schema::users;

        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::last_login.eq(Utc::now()))
            .execute(conn)?;

        Ok(())
    }

    pub fn deactivate_user(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> DatabaseResult<()> {
        use crate::schema::users;

        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::is_active.eq(false))
            .execute(conn)?;

        Ok(())
    }
}

pub struct CredentialRepository;

impl CredentialRepository {
    pub fn create_credential(
        conn: &mut PgConnection,
        new_credential: NewCredential,
    ) -> DatabaseResult<Credential> {
        use crate::schema::credentials;

        let credential = diesel::insert_into(credentials::table)
            .values(&new_credential)
            .returning(Credential::as_returning())
            .get_result(conn)?;

        Ok(credential)
    }

    pub fn get_credential(
        conn: &mut PgConnection,
        credential_id: &[u8],
    ) -> DatabaseResult<Option<Credential>> {
        use crate::schema::credentials;

        let credential = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first(conn)
            .optional()?;

        Ok(credential)
    }

    pub fn get_user_credentials(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> DatabaseResult<Vec<Credential>> {
        use crate::schema::credentials;

        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .filter(credentials::is_active.eq(true))
            .order(credentials::created_at.desc())
            .load(conn)?;

        Ok(credentials)
    }

    pub fn credential_exists(
        conn: &mut PgConnection,
        credential_id: &[u8],
    ) -> DatabaseResult<bool> {
        use crate::schema::credentials;

        let exists = diesel::select(diesel::dsl::exists(
            credentials::table.filter(credentials::credential_id.eq(credential_id))
        )).get_result(conn)?;

        Ok(exists)
    }

    pub fn update_credential_counter(
        conn: &mut PgConnection,
        credential_id: &[u8],
        new_counter: u64,
    ) -> DatabaseResult<()> {
        use crate::schema::credentials;

        diesel::update(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .set((
                credentials::sign_count.eq(new_counter as i64),
                credentials::updated_at.eq(Utc::now()),
            ))
            .execute(conn)?;

        Ok(())
    }

    pub fn update_last_used(
        conn: &mut PgConnection,
        credential_id: &[u8],
        last_used: chrono::DateTime<Utc>,
    ) -> DatabaseResult<()> {
        use crate::schema::credentials;

        diesel::update(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .set((
                credentials::last_used.eq(last_used),
                credentials::updated_at.eq(Utc::now()),
            ))
            .execute(conn)?;

        Ok(())
    }

    pub fn revoke_credential(
        conn: &mut PgConnection,
        credential_id: &[u8],
    ) -> DatabaseResult<()> {
        use crate::schema::credentials;

        diesel::update(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .set((
                credentials::is_active.eq(false),
                credentials::updated_at.eq(Utc::now()),
            ))
            .execute(conn)?;

        Ok(())
    }
}

pub struct ChallengeRepository;

impl ChallengeRepository {
    pub fn create_challenge(
        conn: &mut PgConnection,
        new_challenge: NewChallenge,
    ) -> DatabaseResult<Challenge> {
        use crate::schema::challenges;

        let challenge = diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .returning(Challenge::as_returning())
            .get_result(conn)?;

        Ok(challenge)
    }

    pub fn get_challenge_by_id(
        conn: &mut PgConnection,
        challenge_id: Uuid,
    ) -> DatabaseResult<Option<Challenge>> {
        use crate::schema::challenges;

        let challenge = challenges::table
            .filter(challenges::id.eq(challenge_id))
            .first(conn)
            .optional()?;

        Ok(challenge)
    }

    pub fn mark_challenge_used(
        conn: &mut PgConnection,
        challenge_id: Uuid,
    ) -> DatabaseResult<()> {
        use crate::schema::challenges;

        diesel::update(challenges::table.filter(challenges::id.eq(challenge_id)))
            .set(challenges::used.eq(true))
            .execute(conn)?;

        Ok(())
    }

    pub fn cleanup_expired_challenges(
        conn: &mut PgConnection,
    ) -> DatabaseResult<usize> {
        use crate::schema::challenges;

        let deleted_count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        ).execute(conn)?;

        Ok(deleted_count)
    }
}

pub struct SessionRepository;

impl SessionRepository {
    pub fn create_session(
        conn: &mut PgConnection,
        new_session: NewSession,
    ) -> DatabaseResult<Session> {
        use crate::schema::sessions;

        let session = diesel::insert_into(sessions::table)
            .values(&new_session)
            .returning(Session::as_returning())
            .get_result(conn)?;

        Ok(session)
    }

    pub fn get_session_by_token(
        conn: &mut PgConnection,
        session_token: &str,
    ) -> DatabaseResult<Option<Session>> {
        use crate::schema::sessions;

        let session = sessions::table
            .filter(sessions::session_token.eq(session_token))
            .filter(sessions::is_active.eq(true))
            .filter(sessions::expires_at.gt(Utc::now()))
            .first(conn)
            .optional()?;

        Ok(session)
    }

    pub fn update_session_activity(
        conn: &mut PgConnection,
        session_id: Uuid,
    ) -> DatabaseResult<()> {
        use crate::schema::sessions;

        diesel::update(sessions::table.filter(sessions::id.eq(session_id)))
            .set(sessions::last_activity.eq(Utc::now()))
            .execute(conn)?;

        Ok(())
    }

    pub fn revoke_session(
        conn: &mut PgConnection,
        session_id: Uuid,
    ) -> DatabaseResult<()> {
        use crate::schema::sessions;

        diesel::update(sessions::table.filter(sessions::id.eq(session_id)))
            .set(sessions::is_active.eq(false))
            .execute(conn)?;

        Ok(())
    }

    pub fn revoke_user_sessions(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> DatabaseResult<usize> {
        use crate::schema::sessions;

        let revoked_count = diesel::update(
            sessions::table.filter(sessions::user_id.eq(user_id))
        )
        .set(sessions::is_active.eq(false))
        .execute(conn)?;

        Ok(revoked_count)
    }

    pub fn cleanup_expired_sessions(
        conn: &mut PgConnection,
    ) -> DatabaseResult<usize> {
        use crate::schema::sessions;

        let deleted_count = diesel::delete(
            sessions::table.filter(sessions::expires_at.lt(Utc::now()))
        ).execute(conn)?;

        Ok(deleted_count)
    }
}
```

## 4. API Controllers Implementation

### 4.1 Registration Controller

```rust
// src/controllers/registration.rs
use crate::controllers::JsonResponse;
use crate::error::{ApiError, ApiResult};
use crate::models::{User, RegistrationBeginRequest, RegistrationFinishRequest};
use crate::services::{WebAuthnService, UserService, CredentialService};
use actix_web::{web, HttpRequest, HttpResponse};
use diesel::PgConnection;
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct RegistrationController {
    webauthn_service: Arc<WebAuthnService>,
    user_service: Arc<UserService>,
    credential_service: Arc<CredentialService>,
}

impl RegistrationController {
    pub fn new(
        webauthn_service: Arc<WebAuthnService>,
        user_service: Arc<UserService>,
        credential_service: Arc<CredentialService>,
    ) -> Self {
        Self {
            webauthn_service,
            user_service,
            credential_service,
        }
    }

    pub async fn begin_registration(
        &self,
        req: HttpRequest,
        payload: web::Json<RegistrationBeginRequest>,
        pool: web::Data<crate::db::DbPool>,
    ) -> ApiResult<HttpResponse> {
        let mut conn = pool.get()
            .map_err(|e| {
                error!("Database connection error: {:?}", e);
                ApiError::InternalServerError("Database connection failed".to_string())
            })?;

        // Validate request
        if let Err(e) = payload.validate() {
            warn!("Invalid registration request: {:?}", e);
            return Err(ApiError::BadRequest(e.to_string()));
        }

        // Get or create user
        let user = match self.user_service.get_or_create_user(&mut conn, &payload.username, &payload.display_name).await {
            Ok(user) => user,
            Err(e) => {
                error!("User creation error: {:?}", e);
                return Err(ApiError::InternalServerError("User creation failed".to_string()));
            }
        };

        // Generate registration challenge
        let mut webauthn_service = (*self.webauthn_service).clone();
        let challenge_response = match webauthn_service.generate_registration_challenge(&user).await {
            Ok(response) => response,
            Err(e) => {
                error!("Challenge generation error: {:?}", e);
                return Err(ApiError::InternalServerError("Challenge generation failed".to_string()));
            }
        };

        info!("Registration challenge generated for user: {}", user.username);
        Ok(HttpResponse::Ok().json(JsonResponse::success(challenge_response)))
    }

    pub async fn finish_registration(
        &self,
        req: HttpRequest,
        payload: web::Json<RegistrationFinishRequest>,
        pool: web::Data<crate::db::DbPool>,
    ) -> ApiResult<HttpResponse> {
        let mut conn = pool.get()
            .map_err(|e| {
                error!("Database connection error: {:?}", e);
                ApiError::InternalServerError("Database connection failed".to_string())
            })?;

        // Validate session token
        let session = match self.validate_session(&payload.session_token, &mut conn).await {
            Ok(session) => session,
            Err(e) => {
                warn!("Invalid session token: {:?}", e);
                return Err(ApiError::Unauthorized("Invalid session".to_string()));
            }
        };

        // Verify registration
        let mut webauthn_service = (*self.webauthn_service).clone();
        let registration_result = match webauthn_service.verify_registration(
            payload.registration.clone(),
            &payload.challenge,
        ).await {
            Ok(result) => result,
            Err(e) => {
                warn!("Registration verification failed: {:?}", e);
                return Err(ApiError::BadRequest("Registration verification failed".to_string()));
            }
        };

        // Decode credential ID
        let credential_id = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&registration_result.credential_id) {
            Ok(id) => id,
            Err(e) => {
                error!("Credential ID decoding error: {:?}", e);
                return Err(ApiError::BadRequest("Invalid credential ID".to_string()));
            }
        };

        // Extract public key from registration response
        let public_key = match self.extract_public_key(&payload.registration) {
            Ok(key) => key,
            Err(e) => {
                error!("Public key extraction error: {:?}", e);
                return Err(ApiError::BadRequest("Invalid public key".to_string()));
            }
        };

        // Create credential
        let aaguid = registration_result.aaguid
            .and_then(|aaguid| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&aaguid).ok());

        match self.credential_service.create_credential(
            &mut conn,
            session.user_id,
            &credential_id,
            &public_key,
            &registration_result.attestation_type,
            aaguid.as_deref(),
        ).await {
            Ok(_) => {
                info!("Credential created successfully for user: {}", session.user_id);
                Ok(HttpResponse::Ok().json(JsonResponse::success(registration_result)))
            }
            Err(e) => {
                error!("Credential creation error: {:?}", e);
                Err(ApiError::InternalServerError("Credential creation failed".to_string()))
            }
        }
    }

    async fn validate_session(
        &self,
        session_token: &str,
        conn: &mut PgConnection,
    ) -> Result<crate::models::Session, ApiError> {
        // Implementation for session validation
        todo!("Implement session validation")
    }

    fn extract_public_key(
        &self,
        registration: &crate::models::RegistrationResponse,
    ) -> Result<Vec<u8>, ApiError> {
        // Implementation for extracting public key from attestation
        todo!("Implement public key extraction")
    }
}

// Request/Response models
#[derive(Debug, Deserialize, validator::Validate)]
pub struct RegistrationBeginRequest {
    #[validate(email)]
    pub username: String,
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    #[validate(custom = "validate_user_verification")]
    pub user_verification: Option<String>,
    #[validate(custom = "validate_attestation")]
    pub attestation: Option<String>,
}

#[derive(Debug, Deserialize, validator::Validate)]
pub struct RegistrationFinishRequest {
    pub registration: crate::models::RegistrationResponse,
    #[validate(length(min = 1))]
    pub challenge: String,
    #[validate(length(min = 1))]
    pub session_token: String,
}

// Validation functions
fn validate_user_verification(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "required" | "preferred" | "discouraged" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_user_verification")),
    }
}

fn validate_attestation(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "none" | "indirect" | "direct" | "enterprise" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_attestation")),
    }
}
```

## 5. Security Middleware

### 5.1 Rate Limiting Middleware

```rust
// src/middleware/rate_limit.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::{web, HttpResponse};
use actix_web::dev::{forward_ready, Service, Transform};
use futures::future::{ok, Ready};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{warn, info};

pub struct RateLimiter {
    max_requests: u32,
    window: Duration,
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
}

#[derive(Debug, Clone)]
struct ClientInfo {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn is_allowed(&self, client_ip: &str) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();

        let client_info = clients.entry(client_ip.to_string()).or_insert_with(|| ClientInfo {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(client_info.window_start) > self.window {
            client_info.count = 0;
            client_info.window_start = now;
        }

        // Check if allowed
        if client_info.count >= self.max_requests {
            warn!("Rate limit exceeded for client: {}", client_ip);
            false
        } else {
            client_info.count += 1;
            info!("Request allowed for client: {} (count: {})", client_ip, client_info.count);
            true
        }
    }

    pub fn cleanup_expired_entries(&self) {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        
        clients.retain(|_, info| {
            now.duration_since(info.window_start) <= self.window * 2
        });
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitMiddleware {
            service,
            rate_limiter: self.clone(),
        })
    }
}

pub struct RateLimitMiddleware<S> {
    service: S,
    rate_limiter: RateLimiter,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = futures::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = req
            .connection_info()
            .peer_addr()
            .unwrap_or("unknown")
            .to_string();

        if !self.rate_limiter.is_allowed(&client_ip) {
            let response = HttpResponse::TooManyRequests()
                .json(serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later."
                }))
                .map_into_right_body();

            return Box::pin(async { Ok(req.into_response(response)) });
        }

        let service = self.service.clone();
        Box::pin(async move {
            service.call(req).await
        })
    }
}
```

### 5.2 Security Headers Middleware

```rust
// src/middleware/security.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::{web, HttpResponse};
use actix_web::dev::{forward_ready, Service, Transform};
use futures::future::{ok, Ready};

pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersMiddleware { service })
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = futures::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        
        Box::pin(async move {
            let response = service.call(req).await?;
            
            let response = response.map_into_body().map_into_left_body().map_into_boxed_body();
            
            // Add security headers
            let mut response = response;
            response.headers_mut().insert(
                "X-Content-Type-Options",
                "nosniff".parse().unwrap(),
            );
            response.headers_mut().insert(
                "X-Frame-Options",
                "DENY".parse().unwrap(),
            );
            response.headers_mut().insert(
                "X-XSS-Protection",
                "1; mode=block".parse().unwrap(),
            );
            response.headers_mut().insert(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload".parse().unwrap(),
            );
            response.headers_mut().insert(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';".parse().unwrap(),
            );
            response.headers_mut().insert(
                "Referrer-Policy",
                "strict-origin-when-cross-origin".parse().unwrap(),
            );
            response.headers_mut().insert(
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=()".parse().unwrap(),
            );

            Ok(response)
        })
    }
}
```

This implementation guide provides a comprehensive foundation for building a secure, compliant FIDO2/WebAuthn server. The code examples demonstrate best practices for security, error handling, and maintainability while ensuring FIDO2 compliance.

The implementation follows the test-driven development approach outlined in the test specification, with clear separation of concerns and comprehensive error handling throughout the application.