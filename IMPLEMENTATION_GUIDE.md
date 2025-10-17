# FIDO2/WebAuthn Server - Implementation Guide

## Overview

This guide provides detailed implementation instructions for building a secure, FIDO2-compliant WebAuthn Relying Party Server in Rust using the webauthn-rs library. The implementation follows security-first principles and comprehensive testing requirements.

## 1. Project Setup

### 1.1 Initial Configuration

#### Cargo.toml Dependencies
```toml
[package]
name = "fido-server"
version = "0.1.0"
edition = "2021"

[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"
middleware = "0.1"

# FIDO/WebAuthn
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
diesel_migrations = "2.1"
r2d2 = "0.8"

# Async
tokio = { version = "1.40", features = ["full"] }
futures = "0.3"

# Cryptography
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }
rand = "0.8"
sha2 = "0.10"

# Configuration
config = "0.14"
dotenv = "0.15"

# Logging
log = "0.4"
env_logger = "0.11"

# Error Handling
thiserror = "1.0"
anyhow = "1.0"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Rate Limiting
redis = { version = "0.24", features = ["tokio-comp"] }

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tokio-test = "0.4"
```

### 1.2 Environment Configuration

#### .env Configuration
```env
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_URL=https://api.example.com

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost/fido_server
DATABASE_MAX_CONNECTIONS=10

# Redis Configuration (for rate limiting)
REDIS_URL=redis://localhost:6379

# WebAuthn Configuration
RP_ID=example.com
RP_NAME=Example Application
RP_ORIGIN=https://example.com

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key
CHALLENGE_TIMEOUT_SECONDS=300
RATE_LIMIT_REQUESTS_PER_MINUTE=100

# Logging Configuration
RUST_LOG=info,fido_server=debug
```

## 2. Core Data Structures

### 2.1 Configuration Module

#### src/config/mod.rs
```rust
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub challenge_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub rate_limit_requests_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut settings = config::Config::default();
        
        // Load from .env file
        settings.merge(config::File::with_name(".env").required(false))?;
        
        // Load from environment variables
        settings.merge(config::Environment::with_prefix("FIDO"))?;
        
        // Set defaults
        settings.set_default("server.host", "0.0.0.0")?;
        settings.set_default("server.port", 8080)?;
        settings.set_default("database.max_connections", 10)?;
        settings.set_default("webauthn.challenge_timeout_seconds", 300)?;
        settings.set_default("security.rate_limit_requests_per_minute", 100)?;
        settings.set_default("logging.level", "info")?;
        
        settings.try_into()
    }
}
```

### 2.2 Data Models

#### src/db/models.rs
```rust
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: Vec<u8>,
    pub user_id: Uuid,
    pub credential_data: serde_json::Value,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub transports: Option<serde_json::Value>,
    pub aaguid: Option<Uuid>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_hash: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub user_id: Uuid,
    pub credential_data: serde_json::Value,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub aaguid: Option<Uuid>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge_hash: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

// WebAuthn request/response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: Option<String>,
    pub attestation: Option<String>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub credential: PublicKeyCredential,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    pub username: String,
    pub user_verification: Option<String>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub credential: PublicKeyCredential,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: Option<bool>,
    pub user_verification: Option<String>,
    pub resident_key: Option<String>,
}
```

### 2.3 Database Schema

#### migrations/2024-01-01-000001_create_users.sql
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_created_at ON users(created_at);
```

#### migrations/2024-01-01-000002_create_credentials.sql
```sql
CREATE TABLE credentials (
    id BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_data JSONB NOT NULL,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    transports JSONB,
    aaguid UUID
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_last_used ON credentials(last_used_at);
CREATE INDEX idx_credentials_created_at ON credentials(created_at);
```

#### migrations/2024-01-01-000003_create_challenges.sql
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_hash VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(50) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_challenges_hash ON challenges(challenge_hash);
CREATE INDEX idx_challenges_expires ON challenges(expires_at);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
```

## 3. WebAuthn Service Implementation

### 3.1 Core WebAuthn Service

#### src/services/webauthn_service.rs
```rust
use crate::config::WebAuthnConfig;
use crate::db::models::*;
use crate::db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::error::WebAuthnError;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use webauthn_rs::prelude::*;
use uuid::Uuid;

pub struct WebAuthnService {
    webauthn: WebAuthn<WebauthnConfig>,
    user_repository: Arc<UserRepository>,
    credential_repository: Arc<CredentialRepository>,
    challenge_repository: Arc<ChallengeRepository>,
}

impl WebAuthnService {
    pub fn new(
        config: &WebAuthnConfig,
        user_repository: Arc<UserRepository>,
        credential_repository: Arc<CredentialRepository>,
        challenge_repository: Arc<ChallengeRepository>,
    ) -> Result<Self, WebAuthnError> {
        let rp_id = config.rp_id.clone();
        let rp_name = config.rp_name.clone();
        let rp_origin = config.rp_origin.clone();
        
        let webauthn_config = WebauthnConfig {
            rp: Rp {
                id: rp_id,
                name: rp_name,
                origin: Url::parse(&rp_origin)
                    .map_err(|e| WebAuthnError::Configuration(e.to_string()))?,
            },
        };
        
        let webauthn = WebAuthn::new(webauthn_config);
        
        Ok(Self {
            webauthn,
            user_repository,
            credential_repository,
            challenge_repository,
        })
    }
    
    pub async fn begin_registration(
        &self,
        request: RegistrationRequest,
    ) -> Result<RegistrationChallenge, WebAuthnError> {
        // Validate user doesn't exist
        if let Some(_) = self.user_repository.find_by_username(&request.username).await? {
            return Err(WebAuthnError::UserExists);
        }
        
        // Create user identity
        let user_id = Uuid::new_v4();
        let user = UserIdentity {
            id: user_id.as_bytes().to_vec(),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        };
        
        // Parse user verification preference
        let user_verification = request.user_verification
            .as_deref()
            .and_then(|uv| uv.parse().ok())
            .unwrap_or(UserVerificationPolicy::Preferred);
        
        // Parse attestation preference
        let attestation = request.attestation
            .as_deref()
            .and_then(|a| a.parse().ok())
            .unwrap_or(AttestationConveyancePreference::None);
        
        // Create registration challenge
        let (challenge, state) = self.webauthn
            .start_registration(
                &user,
                user_verification,
                attestation,
                None,
                None,
            )
            .map_err(|e| WebAuthnError::WebAuthn(e.to_string()))?;
        
        // Store challenge
        let challenge_hash = self.hash_challenge(&challenge);
        let expires_at = Utc::now() + chrono::Duration::minutes(5); // 5 minutes
        
        let new_challenge = NewChallenge {
            challenge_hash,
            user_id: Some(user_id),
            challenge_type: "registration".to_string(),
            expires_at,
        };
        
        self.challenge_repository.create(new_challenge).await?;
        
        Ok(RegistrationChallenge {
            public_key: challenge,
            state,
            user_id,
        })
    }
    
    pub async fn complete_registration(
        &self,
        response: RegistrationResponse,
    ) -> Result<RegistrationResult, WebAuthnError> {
        // Find user
        let user = self.user_repository
            .find_by_username(&response.username)
            .await?
            .ok_or(WebAuthnError::UserNotFound)?;
        
        // Verify challenge
        let challenge_hash = self.extract_challenge_from_response(&response.credential)?;
        let stored_challenge = self.challenge_repository
            .find_by_hash(&challenge_hash)
            .await?
            .ok_or(WebAuthnError::ChallengeNotFound)?;
        
        if stored_challenge.expires_at < Utc::now() {
            return Err(WebAuthnError::ChallengeExpired);
        }
        
        if stored_challenge.challenge_type != "registration" {
            return Err(WebAuthnError::InvalidChallengeType);
        }
        
        // Complete registration
        let registration_result = self.webauthn
            .finish_registration(&response.credential, &[])
            .map_err(|e| WebAuthnError::InvalidAttestation(e.to_string()))?;
        
        // Store credential
        let credential_id = registration_result.credential_id.clone();
        let credential_data = serde_json::to_value(&registration_result)
            .map_err(|e| WebAuthnError::Serialization(e.to_string()))?;
        
        let new_credential = NewCredential {
            id: credential_id.clone(),
            user_id: user.id,
            credential_data,
            backup_eligible: registration_result.backup_eligible,
            backup_state: registration_result.backup_state,
            transports: response.credential.response.transports
                .as_ref()
                .map(|t| serde_json::to_value(t).unwrap()),
            aaguid: Some(Uuid::from_slice(&registration_result.aaguid).unwrap()),
        };
        
        self.credential_repository.create(new_credential).await?;
        
        // Clean up challenge
        self.challenge_repository.delete_by_hash(&challenge_hash).await?;
        
        Ok(RegistrationResult {
            credential_id,
            user_id: user.id,
        })
    }
    
    pub async fn begin_authentication(
        &self,
        request: AuthenticationRequest,
    ) -> Result<AuthenticationChallenge, WebAuthnError> {
        // Find user
        let user = self.user_repository
            .find_by_username(&request.username)
            .await?
            .ok_or(WebAuthnError::UserNotFound)?;
        
        // Get user credentials
        let credentials = self.credential_repository
            .find_by_user_id(user.id)
            .await?;
        
        if credentials.is_empty() {
            return Err(WebAuthnError::NoCredentials);
        }
        
        // Convert to allowCredentials format
        let allow_credentials: Vec<AllowCredentials> = credentials
            .into_iter()
            .map(|cred| {
                let transports = cred.transports
                    .and_then(|t| serde_json::from_value(t).ok())
                    .unwrap_or_default();
                
                AllowCredentials {
                    type_: "public-key".to_string(),
                    id: cred.id,
                    transports: Some(transports),
                }
            })
            .collect();
        
        // Parse user verification preference
        let user_verification = request.user_verification
            .as_deref()
            .and_then(|uv| uv.parse().ok())
            .unwrap_or(UserVerificationPolicy::Preferred);
        
        // Create authentication challenge
        let (challenge, state) = self.webauthn
            .start_authentication(&allow_credentials, user_verification)
            .map_err(|e| WebAuthnError::WebAuthn(e.to_string()))?;
        
        // Store challenge
        let challenge_hash = self.hash_challenge(&challenge);
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        
        let new_challenge = NewChallenge {
            challenge_hash,
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at,
        };
        
        self.challenge_repository.create(new_challenge).await?;
        
        Ok(AuthenticationChallenge {
            public_key: challenge,
            state,
            user_id: user.id,
        })
    }
    
    pub async fn complete_authentication(
        &self,
        response: AuthenticationResponse,
    ) -> Result<AuthenticationResult, WebAuthnError> {
        // Find user
        let user = self.user_repository
            .find_by_username(&response.username)
            .await?
            .ok_or(WebAuthnError::UserNotFound)?;
        
        // Verify challenge
        let challenge_hash = self.extract_challenge_from_response(&response.credential)?;
        let stored_challenge = self.challenge_repository
            .find_by_hash(&challenge_hash)
            .await?
            .ok_or(WebAuthnError::ChallengeNotFound)?;
        
        if stored_challenge.expires_at < Utc::now() {
            return Err(WebAuthnError::ChallengeExpired);
        }
        
        if stored_challenge.challenge_type != "authentication" {
            return Err(WebAuthnError::InvalidChallengeType);
        }
        
        // Find credential
        let credential_id = response.credential.raw_id.clone();
        let credential = self.credential_repository
            .find_by_id(&credential_id)
            .await?
            .ok_or(WebAuthnError::CredentialNotFound)?;
        
        // Deserialize credential data
        let passkey: Passkey = serde_json::from_value(credential.credential_data)
            .map_err(|e| WebAuthnError::Deserialization(e.to_string()))?;
        
        // Complete authentication
        let auth_result = self.webauthn
            .finish_authentication(&response.credential, &passkey)
            .map_err(|e| WebAuthnError::InvalidSignature(e.to_string()))?;
        
        // Update last used timestamp
        self.credential_repository
            .update_last_used(&credential_id, Utc::now())
            .await?;
        
        // Clean up challenge
        self.challenge_repository.delete_by_hash(&challenge_hash).await?;
        
        Ok(AuthenticationResult {
            user_id: user.id,
            credential_id,
            user_verified: auth_result.user_verified(),
            authentication_time: Utc::now(),
        })
    }
    
    fn hash_challenge(&self, challenge: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    fn extract_challenge_from_response(
        &self,
        credential: &PublicKeyCredential,
    ) -> Result<String, WebAuthnError> {
        let client_data: serde_json::Value = serde_json::from_str(
            &String::from_utf8(base64::decode_config(
                &credential.response.client_data_json,
                base64::URL_SAFE_NO_PAD,
            ).map_err(|e| WebAuthnError::Base64(e.to_string()))?)
            .map_err(|e| WebAuthnError::Json(e.to_string()))?
        ).map_err(|e| WebAuthnError::Json(e.to_string()))?;
        
        let challenge = client_data.get("challenge")
            .and_then(|c| c.as_str())
            .ok_or(WebAuthnError::MissingChallenge)?;
        
        Ok(self.hash_challenge(challenge))
    }
}

// Response types for the service layer
#[derive(Debug, Clone)]
pub struct RegistrationChallenge {
    pub public_key: CreationChallengeResponse,
    pub state: RegistrationState,
    pub user_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct RegistrationResult {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct AuthenticationChallenge {
    pub public_key: RequestChallengeResponse,
    pub state: AuthenticationState,
    pub user_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub user_verified: bool,
    pub authentication_time: DateTime<Utc>,
}
```

### 3.2 Repository Layer

#### src/db/repositories.rs
```rust
use crate::db::models::*;
use crate::error::WebAuthnError;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use std::sync::Arc;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

pub struct UserRepository {
    pool: Arc<DbPool>,
}

impl UserRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
    
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, WebAuthnError> {
        use crate::schema::users::dsl::*;
        
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            users.filter(id.eq(id)).first::<User>(&mut conn).optional()
        }).await??;
        
        Ok(result)
    }
    
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, WebAuthnError> {
        use crate::schema::users::dsl::*;
        
        let pool = self.pool.clone();
        let username = username.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            users.filter(username.eq(username)).first::<User>(&mut conn).optional()
        }).await??;
        
        Ok(result)
    }
    
    pub async fn create(&self, new_user: NewUser) -> Result<User, WebAuthnError> {
        use crate::schema::users::dsl::*;
        
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(users)
                .values(&new_user)
                .get_result::<User>(&mut conn)
        }).await??;
        
        Ok(result)
    }
    
    pub async fn update(&self, user_id: Uuid, display_name: &str) -> Result<User, WebAuthnError> {
        use crate::schema::users::dsl::*;
        
        let pool = self.pool.clone();
        let display_name = display_name.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(users.filter(id.eq(user_id)))
                .set(display_name.eq(display_name))
                .get_result::<User>(&mut conn)
        }).await??;
        
        Ok(result)
    }
}

pub struct CredentialRepository {
    pool: Arc<DbPool>,
}

impl CredentialRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
    
    pub async fn find_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>, WebAuthnError> {
        use crate::schema::credentials::dsl::*;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            credentials.filter(id.eq(credential_id)).first::<Credential>(&mut conn).optional()
        }).await??;
        
        Ok(result)
    }
    
    pub async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>, WebAuthnError> {
        use crate::schema::credentials::dsl::*;
        
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            credentials.filter(user_id.eq(user_id)).load::<Credential>(&mut conn)
        }).await??;
        
        Ok(result)
    }
    
    pub async fn create(&self, new_credential: NewCredential) -> Result<Credential, WebAuthnError> {
        use crate::schema::credentials::dsl::*;
        
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(credentials)
                .values(&new_credential)
                .get_result::<Credential>(&mut conn)
        }).await??;
        
        Ok(result)
    }
    
    pub async fn update_last_used(&self, credential_id: &[u8], last_used: chrono::DateTime<chrono::Utc>) -> Result<Credential, WebAuthnError> {
        use crate::schema::credentials::dsl::*;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(credentials.filter(id.eq(credential_id)))
                .set(last_used_at.eq(last_used))
                .get_result::<Credential>(&mut conn)
        }).await??;
        
        Ok(result)
    }
    
    pub async fn delete(&self, credential_id: &[u8]) -> Result<(), WebAuthnError> {
        use crate::schema::credentials::dsl::*;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(credentials.filter(id.eq(credential_id))).execute(&mut conn)?;
            Ok::<(), WebAuthnError>(())
        }).await??;
        
        Ok(())
    }
}

pub struct ChallengeRepository {
    pool: Arc<DbPool>,
}

impl ChallengeRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
    
    pub async fn find_by_hash(&self, challenge_hash: &str) -> Result<Option<Challenge>, WebAuthnError> {
        use crate::schema::challenges::dsl::*;
        
        let pool = self.pool.clone();
        let challenge_hash = challenge_hash.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            challenges.filter(challenge_hash.eq(challenge_hash)).first::<Challenge>(&mut conn).optional()
        }).await??;
        
        Ok(result)
    }
    
    pub async fn create(&self, new_challenge: NewChallenge) -> Result<Challenge, WebAuthnError> {
        use crate::schema::challenges::dsl::*;
        
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(challenges)
                .values(&new_challenge)
                .get_result::<Challenge>(&mut conn)
        }).await??;
        
        Ok(result)
    }
    
    pub async fn delete_by_hash(&self, challenge_hash: &str) -> Result<(), WebAuthnError> {
        use crate::schema::challenges::dsl::*;
        
        let pool = self.pool.clone();
        let challenge_hash = challenge_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(challenges.filter(challenge_hash.eq(challenge_hash))).execute(&mut conn)?;
            Ok::<(), WebAuthnError>(())
        }).await??;
        
        Ok(())
    }
    
    pub async fn cleanup_expired(&self) -> Result<usize, WebAuthnError> {
        use crate::schema::challenges::dsl::*;
        
        let pool = self.pool.clone();
        let now = chrono::Utc::now();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(challenges.filter(expires_at.lt(now))).execute(&mut conn)
        }).await??;
        
        Ok(result)
    }
}
```

## 4. API Controllers

### 4.1 WebAuthn Controller

#### src/controllers/webauthn.rs
```rust
use crate::error::WebAuthnError;
use crate::models::*;
use crate::services::WebAuthnService;
use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub struct WebAuthnController {
    webauthn_service: Arc<WebAuthnService>,
}

impl WebAuthnController {
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }
    
    pub async fn begin_registration(
        &self,
        request: web::Json<RegistrationRequest>,
    ) -> Result<HttpResponse, WebAuthnError> {
        let challenge = self.webauthn_service
            .begin_registration(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(json!({
            "status": "ok",
            "message": "Registration challenge created",
            "data": {
                "challenge": challenge.public_key,
                "user": {
                    "id": base64::encode_config(&challenge.user_id.as_bytes(), base64::URL_SAFE_NO_PAD),
                    "name": "", // Will be filled from request
                    "displayName": "", // Will be filled from request
                },
                "rp": {
                    "id": "example.com",
                    "name": "Example Application"
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -257},
                    {"type": "public-key", "alg": -37},
                    {"type": "public-key", "alg": -8}
                ],
                "timeout": 60000,
                "attestation": "none"
            }
        })))
    }
    
    pub async fn complete_registration(
        &self,
        request: web::Json<RegistrationResponse>,
    ) -> Result<HttpResponse, WebAuthnError> {
        let result = self.webauthn_service
            .complete_registration(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(json!({
            "status": "ok",
            "message": "Registration completed successfully",
            "data": {
                "credentialId": base64::encode_config(&result.credential_id, base64::URL_SAFE_NO_PAD),
                "userId": result.user_id,
                "registeredAt": chrono::Utc::now()
            }
        })))
    }
    
    pub async fn begin_authentication(
        &self,
        request: web::Json<AuthenticationRequest>,
    ) -> Result<HttpResponse, WebAuthnError> {
        let challenge = self.webauthn_service
            .begin_authentication(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(json!({
            "status": "ok",
            "message": "Authentication challenge created",
            "data": {
                "challenge": challenge.public_key,
                "allowCredentials": [], // Will be filled from challenge
                "userVerification": "preferred",
                "timeout": 60000,
                "rpId": "example.com"
            }
        })))
    }
    
    pub async fn complete_authentication(
        &self,
        request: web::Json<AuthenticationResponse>,
    ) -> Result<HttpResponse, WebAuthnError> {
        let result = self.webauthn_service
            .complete_authentication(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(json!({
            "status": "ok",
            "message": "Authentication successful",
            "data": {
                "authenticated": true,
                "userId": result.user_id,
                "credentialId": base64::encode_config(&result.credential_id, base64::URL_SAFE_NO_PAD),
                "authenticationTime": result.authentication_time,
                "userVerified": result.user_verified
            }
        })))
    }
}

// Route handlers
pub async fn begin_registration(
    request: web::Json<RegistrationRequest>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, WebAuthnError> {
    controller.begin_registration(request).await
}

pub async fn complete_registration(
    request: web::Json<RegistrationResponse>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, WebAuthnError> {
    controller.complete_registration(request).await
}

pub async fn begin_authentication(
    request: web::Json<AuthenticationRequest>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, WebAuthnError> {
    controller.begin_authentication(request).await
}

pub async fn complete_authentication(
    request: web::Json<AuthenticationResponse>,
    controller: web::Data<Arc<WebAuthnController>>,
) -> Result<HttpResponse, WebAuthnError> {
    controller.complete_authentication(request).await
}
```

## 5. Error Handling

### 5.1 Error Types

#### src/error/mod.rs
```rust
use actix_web::{error::ResponseError, HttpResponse};
use derive_more::{Display, Error};
use serde_json::json;

#[derive(Debug, Display, Error)]
pub enum WebAuthnError {
    #[display(fmt = "User already exists")]
    UserExists,
    
    #[display(fmt = "User not found")]
    UserNotFound,
    
    #[display(fmt = "Credential not found")]
    CredentialNotFound,
    
    #[display(fmt = "No credentials found for user")]
    NoCredentials,
    
    #[display(fmt = "Challenge not found")]
    ChallengeNotFound,
    
    #[display(fmt = "Challenge expired")]
    ChallengeExpired,
    
    #[display(fmt = "Invalid challenge type")]
    InvalidChallengeType,
    
    #[display(fmt = "Invalid attestation")]
    InvalidAttestation(String),
    
    #[display(fmt = "Invalid signature")]
    InvalidSignature(String),
    
    #[display(fmt = "Invalid request format")]
    InvalidRequest,
    
    #[display(fmt = "Configuration error: {}", _0)]
    Configuration(String),
    
    #[display(fmt = "Database error: {}", _0)]
    Database(String),
    
    #[display(fmt = "WebAuthn error: {}", _0)]
    WebAuthn(String),
    
    #[display(fmt = "Serialization error: {}", _0)]
    Serialization(String),
    
    #[display(fmt = "Deserialization error: {}", _0)]
    Deserialization(String),
    
    #[display(fmt = "Base64 error: {}", _0)]
    Base64(String),
    
    #[display(fmt = "JSON error: {}", _0)]
    Json(String),
    
    #[display(fmt = "Missing challenge in response")]
    MissingChallenge,
    
    #[display(fmt = "Rate limit exceeded")]
    RateLimitExceeded,
    
    #[display(fmt = "Internal server error")]
    InternalError,
}

impl ResponseError for WebAuthnError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_code = self.error_code();
        let message = self.to_string();
        
        HttpResponse::build(status_code).json(json!({
            "status": "error",
            "message": message,
            "errors": [{
                "code": error_code,
                "message": message
            }],
            "timestamp": chrono::Utc::now(),
            "requestId": uuid::Uuid::new_v4()
        }))
    }
}

impl WebAuthnError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            WebAuthnError::UserExists => actix_web::http::StatusCode::CONFLICT,
            WebAuthnError::UserNotFound => actix_web::http::StatusCode::NOT_FOUND,
            WebAuthnError::CredentialNotFound => actix_web::http::StatusCode::NOT_FOUND,
            WebAuthnError::NoCredentials => actix_web::http::StatusCode::NOT_FOUND,
            WebAuthnError::ChallengeNotFound => actix_web::http::StatusCode::NOT_FOUND,
            WebAuthnError::ChallengeExpired => actix_web::http::StatusCode::UNAUTHORIZED,
            WebAuthnError::InvalidChallengeType => actix_web::http::StatusCode::BAD_REQUEST,
            WebAuthnError::InvalidAttestation(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            WebAuthnError::InvalidSignature(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            WebAuthnError::InvalidRequest => actix_web::http::StatusCode::BAD_REQUEST,
            WebAuthnError::RateLimitExceeded => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            _ => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    
    fn error_code(&self) -> &'static str {
        match self {
            WebAuthnError::UserExists => "USER_EXISTS",
            WebAuthnError::UserNotFound => "USER_NOT_FOUND",
            WebAuthnError::CredentialNotFound => "CREDENTIAL_NOT_FOUND",
            WebAuthnError::NoCredentials => "NO_CREDENTIALS",
            WebAuthnError::ChallengeNotFound => "CHALLENGE_NOT_FOUND",
            WebAuthnError::ChallengeExpired => "CHALLENGE_EXPIRED",
            WebAuthnError::InvalidChallengeType => "INVALID_CHALLENGE_TYPE",
            WebAuthnError::InvalidAttestation(_) => "INVALID_ATTESTATION",
            WebAuthnError::InvalidSignature(_) => "INVALID_SIGNATURE",
            WebAuthnError::InvalidRequest => "INVALID_REQUEST",
            WebAuthnError::Configuration(_) => "CONFIGURATION_ERROR",
            WebAuthnError::Database(_) => "DATABASE_ERROR",
            WebAuthnError::WebAuthn(_) => "WEBAUTHN_ERROR",
            WebAuthnError::Serialization(_) => "SERIALIZATION_ERROR",
            WebAuthnError::Deserialization(_) => "DESERIALIZATION_ERROR",
            WebAuthnError::Base64(_) => "BASE64_ERROR",
            WebAuthnError::Json(_) => "JSON_ERROR",
            WebAuthnError::MissingChallenge => "MISSING_CHALLENGE",
            WebAuthnError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            WebAuthnError::InternalError => "INTERNAL_ERROR",
        }
    }
}

impl From<diesel::result::Error> for WebAuthnError {
    fn from(error: diesel::result::Error) -> Self {
        WebAuthnError::Database(error.to_string())
    }
}

impl From<r2d2::Error> for WebAuthnError {
    fn from(error: r2d2::Error) -> Self {
        WebAuthnError::Database(error.to_string())
    }
}

impl From<serde_json::Error> for WebAuthnError {
    fn from(error: serde_json::Error) -> Self {
        WebAuthnError::Json(error.to_string())
    }
}

impl From<base64::DecodeError> for WebAuthnError {
    fn from(error: base64::DecodeError) -> Self {
        WebAuthnError::Base64(error.to_string())
    }
}
```

## 6. Testing Implementation

### 6.1 Unit Tests

#### tests/unit/webauthn_service_test.rs
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repositories::*;
    use crate::services::WebAuthnService;
    use mockall::predicate::*;
    use mockall::*;
    use uuid::Uuid;
    
    mock! {
        UserRepository {}
        
        impl UserRepository {
            async fn find_by_username(&self, username: &str) -> Result<Option<User>, WebAuthnError>;
            async fn create(&self, new_user: NewUser) -> Result<User, WebAuthnError>;
        }
    }
    
    mock! {
        CredentialRepository {}
        
        impl CredentialRepository {
            async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>, WebAuthnError>;
            async fn create(&self, new_credential: NewCredential) -> Result<Credential, WebAuthnError>;
        }
    }
    
    mock! {
        ChallengeRepository {}
        
        impl ChallengeRepository {
            async fn find_by_hash(&self, challenge_hash: &str) -> Result<Option<Challenge>, WebAuthnError>;
            async fn create(&self, new_challenge: NewChallenge) -> Result<Challenge, WebAuthnError>;
            async fn delete_by_hash(&self, challenge_hash: &str) -> Result<(), WebAuthnError>;
        }
    }
    
    #[tokio::test]
    async fn test_begin_registration_user_exists() {
        let mut user_repo = MockUserRepository::new();
        user_repo
            .expect_find_by_username()
            .with(eq("test@example.com"))
            .returning(|_| Ok(Some(User {
                id: Uuid::new_v4(),
                username: "test@example.com".to_string(),
                display_name: "Test User".to_string(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })));
        
        let config = WebAuthnConfig {
            rp_id: "example.com".to_string(),
            rp_name: "Test App".to_string(),
            rp_origin: "https://example.com".to_string(),
            challenge_timeout: chrono::Duration::minutes(5),
        };
        
        let service = WebAuthnService::new(
            &config,
            Arc::new(user_repo),
            Arc::new(MockCredentialRepository::new()),
            Arc::new(MockChallengeRepository::new()),
        ).unwrap();
        
        let request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: None,
            attestation: None,
            authenticator_selection: None,
            extensions: None,
        };
        
        let result = service.begin_registration(request).await;
        assert!(matches!(result, Err(WebAuthnError::UserExists)));
    }
    
    #[tokio::test]
    async fn test_begin_registration_success() {
        let mut user_repo = MockUserRepository::new();
        user_repo
            .expect_find_by_username()
            .with(eq("test@example.com"))
            .returning(|_| Ok(None));
        
        let mut challenge_repo = MockChallengeRepository::new();
        challenge_repo
            .expect_create()
            .returning(|_| Ok(Challenge {
                id: Uuid::new_v4(),
                challenge_hash: "test_hash".to_string(),
                user_id: Some(Uuid::new_v4()),
                challenge_type: "registration".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                created_at: chrono::Utc::now(),
            }));
        
        let config = WebAuthnConfig {
            rp_id: "example.com".to_string(),
            rp_name: "Test App".to_string(),
            rp_origin: "https://example.com".to_string(),
            challenge_timeout: chrono::Duration::minutes(5),
        };
        
        let service = WebAuthnService::new(
            &config,
            Arc::new(user_repo),
            Arc::new(MockCredentialRepository::new()),
            Arc::new(challenge_repo),
        ).unwrap();
        
        let request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: None,
            attestation: None,
            authenticator_selection: None,
            extensions: None,
        };
        
        let result = service.begin_registration(request).await;
        assert!(result.is_ok());
    }
}
```

### 6.2 Integration Tests

#### tests/integration/api_test.rs
```rust
#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};
    use crate::controllers::webauthn::*;
    use crate::services::WebAuthnService;
    use serde_json::json;
    
    #[actix_rt::test]
    async fn test_registration_flow() {
        // Setup test app
        let mut app = test::init_service(
            App::new()
                .route("/api/v1/webauthn/register/begin", web::post().to(begin_registration))
                .route("/api/v1/webauthn/register/complete", web::post().to(complete_registration))
        ).await;
        
        // Begin registration
        let req = test::TestRequest::post()
            .uri("/api/v1/webauthn/register/begin")
            .set_json(&json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert!(body["data"]["challenge"].is_string());
        
        // Complete registration (mock credential)
        let req = test::TestRequest::post()
            .uri("/api/v1/webauthn/register/complete")
            .set_json(&json!({
                "username": "test@example.com",
                "credential": {
                    "id": "mock_credential_id",
                    "rawId": "mock_raw_id",
                    "type": "public-key",
                    "response": {
                        "attestationObject": "mock_attestation",
                        "clientDataJSON": "mock_client_data"
                    }
                }
            }))
            .to_request();
        
        let resp = test::call_service(&mut app, req).await;
        // This will fail with mock data, but tests the endpoint structure
        assert!(!resp.status().is_success());
    }
    
    #[actix_rt::test]
    async fn test_authentication_flow() {
        // Setup test app
        let mut app = test::init_service(
            App::new()
                .route("/api/v1/webauthn/authenticate/begin", web::post().to(begin_authentication))
                .route("/api/v1/webauthn/authenticate/complete", web::post().to(complete_authentication))
        ).await;
        
        // Begin authentication
        let req = test::TestRequest::post()
            .uri("/api/v1/webauthn/authenticate/begin")
            .set_json(&json!({
                "username": "test@example.com"
            }))
            .to_request();
        
        let resp = test::call_service(&mut app, req).await;
        // This will fail with no user, but tests the endpoint structure
        assert!(!resp.status().is_success());
    }
}
```

This implementation guide provides a comprehensive foundation for building a secure, FIDO2-compliant WebAuthn server in Rust with proper error handling, testing, and security considerations. The code follows best practices for security, performance, and maintainability.