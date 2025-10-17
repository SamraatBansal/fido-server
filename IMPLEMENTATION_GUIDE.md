# FIDO2/WebAuthn Server Implementation Guide

## Overview

This guide provides detailed implementation instructions for building a secure, FIDO2-compliant WebAuthn Relying Party Server in Rust using the webauthn-rs library.

## 1. Project Setup

### 1.1 Initial Configuration

#### Cargo.toml Dependencies
```toml
[package]
name = "fido-server"
version = "0.1.0"
edition = "2021"
authors = ["FIDO Server Team"]
license = "MIT"

[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"

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

# Security
ring = "0.17"
subtle = "2.5"

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tempfile = "3.10"
tokio-test = "0.4"
proptest = "1.5"
criterion = "0.5"
testcontainers = "0.15"
```

#### Environment Configuration
```bash
# .env
DATABASE_URL=postgres://postgres:password@localhost/fido_server
RUST_LOG=info
SERVER_HOST=0.0.0.0
SERVER_PORT=8443
TLS_CERT_PATH=/path/to/cert.pem
TLS_KEY_PATH=/path/to/key.pem
RP_ID=localhost
RP_NAME=FIDO Test Server
ORIGIN=https://localhost:8443
CHALLENGE_TIMEOUT_SECONDS=300
RATE_LIMIT_REQUESTS_PER_MINUTE=60
```

### 1.2 Database Setup

#### Diesel Setup
```bash
# Install diesel CLI
cargo install diesel_cli --no-default-features --features postgres

# Setup database
diesel setup

# Create migrations
diesel migration generate create_users_table
diesel migration generate create_credentials_table
diesel migration generate create_challenges_table
diesel migration generate create_audit_logs_table
```

#### Migration Files

**migrations/2023-01-01-000001_create_users_table/up.sql**
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_user_handle ON users(user_handle);
```

**migrations/2023-01-01-000002_create_credentials_table/up.sql**
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    user_verified BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_last_used ON credentials(last_used);
```

## 2. Core Implementation

### 2.1 Configuration Module

#### src/config/mod.rs
```rust
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub challenge_timeout_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    pub rate_limit_requests_per_minute: u32,
    pub max_concurrent_sessions: u32,
    pub session_timeout_minutes: u32,
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
        settings.set_default("server.port", 8443)?;
        settings.set_default("database.max_connections", 10)?;
        settings.set_default("database.min_connections", 1)?;
        settings.set_default("database.connection_timeout_seconds", 30)?;
        settings.set_default("webauthn.challenge_timeout_seconds", 300)?;
        settings.set_default("security.rate_limit_requests_per_minute", 60)?;
        settings.set_default("security.max_concurrent_sessions", 10)?;
        settings.set_default("security.session_timeout_minutes", 30)?;
        
        settings.try_into()
    }
    
    pub fn challenge_timeout(&self) -> Duration {
        Duration::from_secs(self.webauthn.challenge_timeout_seconds)
    }
}
```

#### src/config/settings.rs
```rust
use crate::config::Config;
use std::sync::OnceLock;

static CONFIG: OnceLock<Config> = OnceLock::new();

pub fn init_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    CONFIG.set(config).map_err(|_| "Config already initialized")?;
    Ok(())
}

pub fn get_config() -> &'static Config {
    CONFIG.get().expect("Config not initialized")
}
```

### 2.2 Error Handling

#### src/error/mod.rs
```rust
use thiserror::Error;

pub type Result<T> = std::result::Result<T, FidoError>;

#[derive(Error, Debug)]
pub enum FidoError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    
    #[error("Duplicate credential: {0}")]
    DuplicateCredential(String),
    
    #[error("Challenge expired or invalid")]
    InvalidChallenge,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Invalid origin")]
    InvalidOrigin,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl actix_web::error::ResponseError for FidoError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            FidoError::InvalidInput(msg) => {
                actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            },
            FidoError::UserNotFound(_) | FidoError::CredentialNotFound(_) => {
                actix_web::HttpResponse::NotFound().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Resource not found"
                }))
            },
            FidoError::DuplicateCredential(_) => {
                actix_web::HttpResponse::Conflict().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Credential already exists"
                }))
            },
            FidoError::InvalidChallenge | FidoError::InvalidSignature | FidoError::InvalidOrigin => {
                actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": self.to_string()
                }))
            },
            FidoError::RateLimitExceeded => {
                actix_web::HttpResponse::TooManyRequests().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Rate limit exceeded"
                }))
            },
            _ => {
                log::error!("Internal error: {}", self);
                actix_web::HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Internal server error"
                }))
            }
        }
    }
}
```

### 2.3 Database Models

#### src/db/models.rs
```rust
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::audit_logs)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub credential_id: Option<Uuid>,
    pub event_type: String,
    pub event_data: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::audit_logs)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub credential_id: Option<Uuid>,
    pub event_type: String,
    pub event_data: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}
```

### 2.4 Database Repositories

#### src/db/repositories.rs
```rust
use crate::db::models::*;
use crate::error::{FidoError, Result};
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use std::sync::Arc;

pub type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &NewUser) -> Result<User>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn find_by_user_handle(&self, user_handle: &[u8]) -> Result<Option<User>>;
    async fn update_last_login(&self, user_id: &Uuid) -> Result<()>;
}

pub trait CredentialRepository: Send + Sync {
    async fn save_credential(&self, credential: &NewCredential) -> Result<()>;
    async fn find_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
    async fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()>;
    async fn update_last_used(&self, credential_id: &[u8]) -> Result<()>;
    async fn delete_credential(&self, credential_id: &[u8]) -> Result<()>;
}

pub trait ChallengeRepository: Send + Sync {
    async fn save_challenge(&self, challenge: &NewChallenge) -> Result<()>;
    async fn find_and_consume_challenge(&self, challenge: &[u8]) -> Result<Option<Challenge>>;
    async fn cleanup_expired_challenges(&self) -> Result<()>;
}

pub trait AuditLogRepository: Send + Sync {
    async fn log_event(&self, log: &NewAuditLog) -> Result<()>;
    async fn find_user_events(&self, user_id: &Uuid, limit: i64) -> Result<Vec<AuditLog>>;
}

pub struct PostgresUserRepository {
    pool: DbPool,
}

impl PostgresUserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(&self, user: &NewUser) -> Result<User> {
        use crate::schema::users;
        
        let pool = self.pool.clone();
        let user_clone = user.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(users::table)
                .values(&user_clone)
                .returning(User::as_returning())
                .get_result(&mut conn)
                .map_err(FidoError::from)
        }).await?
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        use crate::schema::users;
        
        let pool = self.pool.clone();
        let username = username.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            users::table
                .filter(users::username.eq(&username))
                .first::<User>(&mut conn)
                .optional()
                .map_err(FidoError::from)
        }).await?
    }

    async fn find_by_user_handle(&self, user_handle: &[u8]) -> Result<Option<User>> {
        use crate::schema::users;
        
        let pool = self.pool.clone();
        let user_handle = user_handle.to_vec();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            users::table
                .filter(users::user_handle.eq(&user_handle))
                .first::<User>(&mut conn)
                .optional()
                .map_err(FidoError::from)
        }).await?
    }

    async fn update_last_login(&self, user_id: &Uuid) -> Result<()> {
        use crate::schema::users;
        
        let pool = self.pool.clone();
        let user_id = *user_id;
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(users::table.find(user_id))
                .set(users::last_login.eq(Utc::now()))
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }
}

pub struct PostgresCredentialRepository {
    pool: DbPool,
}

impl PostgresCredentialRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn save_credential(&self, credential: &NewCredential) -> Result<()> {
        use crate::schema::credentials;
        
        let pool = self.pool.clone();
        let credential_clone = credential.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(credentials::table)
                .values(&credential_clone)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }

    async fn find_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        use crate::schema::credentials;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            credentials::table
                .filter(credentials::credential_id.eq(&credential_id))
                .first::<Credential>(&mut conn)
                .optional()
                .map_err(FidoError::from)
        }).await?
    }

    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        use crate::schema::credentials;
        
        let pool = self.pool.clone();
        let user_id = *user_id;
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            credentials::table
                .filter(credentials::user_id.eq(user_id))
                .load::<Credential>(&mut conn)
                .map_err(FidoError::from)
        }).await?
    }

    async fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()> {
        use crate::schema::credentials;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(credentials::table.filter(credentials::credential_id.eq(&credential_id)))
                .set((
                    credentials::sign_count.eq(sign_count),
                    credentials::updated_at.eq(Utc::now()),
                ))
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }

    async fn update_last_used(&self, credential_id: &[u8]) -> Result<()> {
        use crate::schema::credentials;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(credentials::table.filter(credentials::credential_id.eq(&credential_id)))
                .set(credentials::last_used.eq(Utc::now()))
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> Result<()> {
        use crate::schema::credentials;
        
        let pool = self.pool.clone();
        let credential_id = credential_id.to_vec();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(credentials::table.filter(credentials::credential_id.eq(&credential_id)))
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }
}

pub struct PostgresChallengeRepository {
    pool: DbPool,
}

impl PostgresChallengeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ChallengeRepository for PostgresChallengeRepository {
    async fn save_challenge(&self, challenge: &NewChallenge) -> Result<()> {
        use crate::schema::challenges;
        
        let pool = self.pool.clone();
        let challenge_clone = challenge.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(challenges::table)
                .values(&challenge_clone)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }

    async fn find_and_consume_challenge(&self, challenge: &[u8]) -> Result<Option<Challenge>> {
        use crate::schema::challenges;
        
        let pool = self.pool.clone();
        let challenge = challenge.to_vec();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            conn.transaction::<Option<Challenge>, _, _>(|conn| {
                let found_challenge = challenges::table
                    .filter(challenges::challenge.eq(&challenge))
                    .filter(challenges::used.eq(false))
                    .filter(challenges::expires_at.gt(Utc::now()))
                    .first::<Challenge>(conn)
                    .optional()?;

                if let Some(ref challenge) = found_challenge {
                    diesel::update(challenges::table.find(challenge.id))
                        .set(challenges::used.eq(true))
                        .execute(conn)?;
                }

                Ok(found_challenge)
            })
            .map_err(FidoError::from)
        }).await?
    }

    async fn cleanup_expired_challenges(&self) -> Result<()> {
        use crate::schema::challenges;
        
        let pool = self.pool.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(
                challenges::table
                    .filter(challenges::expires_at.lt(Utc::now()))
                    .or(challenges::used.eq(true))
            )
            .execute(&mut conn)
            .map(|_| ())
            .map_err(FidoError::from)
        }).await?
    }
}

pub struct PostgresAuditLogRepository {
    pool: DbPool,
}

impl PostgresAuditLogRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AuditLogRepository for PostgresAuditLogRepository {
    async fn log_event(&self, log: &NewAuditLog) -> Result<()> {
        use crate::schema::audit_logs;
        
        let pool = self.pool.clone();
        let log_clone = log.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(audit_logs::table)
                .values(&log_clone)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(FidoError::from)
        }).await?
    }

    async fn find_user_events(&self, user_id: &Uuid, limit: i64) -> Result<Vec<AuditLog>> {
        use crate::schema::audit_logs;
        
        let pool = self.pool.clone();
        let user_id = *user_id;
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            audit_logs::table
                .filter(audit_logs::user_id.eq(user_id))
                .order(audit_logs::created_at.desc())
                .limit(limit)
                .load::<AuditLog>(&mut conn)
                .map_err(FidoError::from)
        }).await?
    }
}
```

### 2.5 WebAuthn Service

#### src/services/webauthn.rs
```rust
use crate::config::get_config;
use crate::db::repositories::{CredentialRepository, ChallengeRepository, UserRepository};
use crate::error::{FidoError, Result};
use crate::models::*;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnService {
    webauthn: Arc<Webauthn>,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    challenge_repo: Arc<dyn ChallengeRepository>,
}

impl WebAuthnService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        challenge_repo: Arc<dyn ChallengeRepository>,
    ) -> Result<Self> {
        let config = get_config();
        
        let rp = RelyingParty {
            id: config.webauthn.rp_id.clone(),
            name: config.webauthn.rp_name.clone(),
            origin: Url::parse(&config.webauthn.rp_origin)
                .map_err(|e| FidoError::InvalidInput(format!("Invalid origin URL: {}", e)))?,
        };

        let webauthn = WebauthnBuilder::new(rp)
            .map_err(|e| FidoError::InvalidInput(format!("WebAuthn builder error: {}", e)))?
            .build();

        Ok(Self {
            webauthn: Arc::new(webauthn),
            user_repo,
            credential_repo,
            challenge_repo,
        })
    }

    pub async fn generate_attestation_challenge(
        &self,
        request: &AttestationOptionsRequest,
    ) -> Result<AttestationOptionsResponse> {
        // Validate input
        self.validate_attestation_request(request)?;

        // Check if user already exists
        let existing_user = self.user_repo.find_by_username(&request.username).await?;
        if existing_user.is_some() {
            return Err(FidoError::InvalidInput("User already exists".to_string()));
        }

        // Create user handle
        let user_handle = self.generate_user_handle();

        // Generate challenge
        let challenge = self.generate_challenge();

        // Create user for WebAuthn
        let user = User {
            id: Uuid::new_v4(),
            name: request.username.clone(),
            display_name: request.displayName.clone(),
            credentials: Vec::new(),
        };

        // Generate attestation options
        let attestation = request.attestation.as_deref().unwrap_or("none");
        let attestation = match attestation {
            "none" => AttestationConveyancePreference::None,
            "direct" => AttestationConveyancePreference::Direct,
            "indirect" => AttestationConveyancePreference::Indirect,
            "enterprise" => AttestationConveyancePreference::Enterprise,
            _ => return Err(FidoError::InvalidInput("Invalid attestation format".to_string())),
        };

        let user_verification = request.authenticatorSelection.as_ref()
            .and_then(|as_| as_.userVerification.as_deref())
            .unwrap_or("preferred");
        
        let user_verification = match user_verification {
            "required" => UserVerificationPolicy::Required,
            "preferred" => UserVerificationPolicy::Preferred,
            "discouraged" => UserVerificationPolicy::Discouraged,
            _ => return Err(FidoError::InvalidInput("Invalid user verification policy".to_string())),
        };

        let authenticator_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: request.authenticatorSelection.as_ref()
                .and_then(|as_| as_.authenticatorAttachment.as_deref())
                .and_then(|aa| match aa {
                    "platform" => Some(AuthenticatorAttachment::Platform),
                    "cross-platform" => Some(AuthenticatorAttachment::CrossPlatform),
                    _ => None,
                }),
            require_resident_key: request.authenticatorSelection.as_ref()
                .and_then(|as_| as_.requireResidentKey)
                .unwrap_or(false),
            user_verification,
        };

        let (challenge_ccr, state) = self.webauthn
            .generate_challenge_register_options(
                &user,
                authenticator_selection,
                attestation,
                None,
            )
            .map_err(|e| FidoError::WebAuthn(e))?;

        // Store challenge
        let challenge_bytes = challenge_ccr.challenge.as_bytes().to_vec();
        let new_challenge = NewChallenge {
            challenge: challenge_bytes.clone(),
            user_id: None, // Will be set after user creation
            challenge_type: "attestation".to_string(),
            expires_at: Utc::now() + get_config().challenge_timeout(),
        };

        self.challenge_repo.save_challenge(&new_challenge).await?;

        // Convert to response format
        let response = AttestationOptionsResponse {
            status: "ok".to_string(),
            errorMessage: String::new(),
            challenge: general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes),
            rp: RpInfo {
                name: get_config().webauthn.rp_name.clone(),
                id: get_config().webauthn.rp_id.clone(),
            },
            user: UserInfo {
                id: general_purpose::URL_SAFE_NO_PAD.encode(&user_handle),
                name: request.username.clone(),
                displayName: request.displayName.clone(),
            },
            pubKeyCredParams: vec![
                PublicKeyCredentialParameters {
                    type_: "public-key".to_string(),
                    alg: -7, // ES256
                },
                PublicKeyCredentialParameters {
                    type_: "public-key".to_string(),
                    alg: -257, // RS256
                },
            ],
            timeout: (get_config().webauthn.challenge_timeout_seconds * 1000) as u32,
            attestation: attestation.to_string(),
            authenticatorSelection: request.authenticatorSelection.clone(),
            extensions: serde_json::json!({}),
        };

        Ok(response)
    }

    pub async fn verify_attestation(
        &self,
        request: &AttestationResultRequest,
    ) -> Result<AttestationResultResponse> {
        // Decode credential ID
        let credential_id = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.id)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid credential ID: {}", e)))?;

        // Check for duplicate credential
        let existing_credential = self.credential_repo.find_by_id(&credential_id).await?;
        if existing_credential.is_some() {
            return Err(FidoError::DuplicateCredential(request.id.clone()));
        }

        // Decode attestation object and client data
        let attestation_object = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.response.attestationObject)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid attestation object: {}", e)))?;

        let client_data_json = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.response.clientDataJSON)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid client data JSON: {}", e)))?;

        // Extract challenge from client data
        let client_data: ClientData = serde_json::from_slice(&client_data_json)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid client data: {}", e)))?;

        // Validate origin
        if client_data.origin.as_str() != get_config().webauthn.rp_origin {
            return Err(FidoError::InvalidOrigin);
        }

        // Validate challenge
        let challenge_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid challenge: {}", e)))?;

        let stored_challenge = self.challenge_repo
            .find_and_consume_challenge(&challenge_bytes)
            .await?;

        if stored_challenge.is_none() {
            return Err(FidoError::InvalidChallenge);
        }

        // Create attestation response for webauthn-rs
        let attestation_response = AuthenticatorAttestationResponseRaw {
            attestation_object,
            client_data_json,
        };

        let public_key_credential = PublicKeyCredential {
            id: request.id.clone(),
            raw_id: credential_id.clone(),
            response: attestation_response,
            type_: "public-key".to_string(),
            client_extension_results: request.clientExtensionResults.clone(),
            authenticator_attachment: None,
        };

        // Verify attestation
        let attestation_result = self.webauthn
            .register_credential(&public_key_credential, &state)
            .map_err(|e| FidoError::WebAuthn(e))?;

        // Extract user info from client data
        let user_info: UserInfo = serde_json::from_str(&client_data_json)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid user info: {}", e)))?;

        let user_handle = general_purpose::URL_SAFE_NO_PAD
            .decode(&user_info.id)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid user handle: {}", e)))?;

        // Create or find user
        let user = match self.user_repo.find_by_user_handle(&user_handle).await? {
            Some(user) => user,
            None => {
                let new_user = NewUser {
                    username: user_info.name,
                    display_name: user_info.displayName,
                    user_handle,
                };
                self.user_repo.create_user(&new_user).await?
            }
        };

        // Store credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: credential_id.clone(),
            credential_public_key: attestation_result.credential.public_key().to_vec(),
            attestation_type: attestation_result.attestation_format().to_string(),
            aaguid: Some(attestation_result.credential.aaguid().to_vec()),
            sign_count: attestation_result.credential.counter() as i64,
            user_verified: attestation_result.credential.user_verified(),
            backup_eligible: attestation_result.credential.backup_eligible(),
            backup_state: attestation_result.credential.backup_state(),
            transports: Some(serde_json::to_value(attestation_result.credential.transports())?),
        };

        self.credential_repo.save_credential(&new_credential).await?;

        Ok(AttestationResultResponse {
            status: "ok".to_string(),
            errorMessage: String::new(),
            credentialId: request.id.clone(),
        })
    }

    pub async fn generate_assertion_challenge(
        &self,
        request: &AssertionOptionsRequest,
    ) -> Result<AssertionOptionsResponse> {
        // Find user if username provided
        let user = if let Some(username) = &request.username {
            Some(self.user_repo.find_by_username(username).await?
                .ok_or(FidoError::UserNotFound(username.clone()))?)
        } else {
            None
        };

        // Get user credentials
        let credentials = if let Some(ref user) = user {
            self.credential_repo.find_by_user_id(&user.id).await?
        } else {
            Vec::new()
        };

        // Generate challenge
        let challenge = self.generate_challenge();

        // Create allow credentials list
        let allow_credentials: Vec<AllowCredentials> = credentials
            .into_iter()
            .map(|cred| AllowCredentials {
                type_: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: cred.transports
                    .and_then(|t| serde_json::from_value(t).ok())
                    .unwrap_or_default(),
            })
            .collect();

        // Store challenge
        let challenge_bytes = challenge.as_bytes().to_vec();
        let user_id = user.as_ref().map(|u| u.id);
        let new_challenge = NewChallenge {
            challenge: challenge_bytes.clone(),
            user_id,
            challenge_type: "assertion".to_string(),
            expires_at: Utc::now() + get_config().challenge_timeout(),
        };

        self.challenge_repo.save_challenge(&new_challenge).await?;

        let user_verification = request.userVerification.as_deref().unwrap_or("preferred");
        let user_verification = match user_verification {
            "required" => UserVerificationPolicy::Required,
            "preferred" => UserVerificationPolicy::Preferred,
            "discouraged" => UserVerificationPolicy::Discouraged,
            _ => return Err(FidoError::InvalidInput("Invalid user verification policy".to_string())),
        };

        Ok(AssertionOptionsResponse {
            status: "ok".to_string(),
            errorMessage: String::new(),
            challenge: general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes),
            allowCredentials,
            userVerification: user_verification.to_string(),
            timeout: (get_config().webauthn.challenge_timeout_seconds * 1000) as u32,
            extensions: serde_json::json!({}),
        })
    }

    pub async fn verify_assertion(
        &self,
        request: &AssertionResultRequest,
    ) -> Result<AssertionResultResponse> {
        // Decode credential ID
        let credential_id = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.id)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid credential ID: {}", e)))?;

        // Find credential
        let credential = self.credential_repo.find_by_id(&credential_id).await?
            .ok_or(FidoError::CredentialNotFound(request.id.clone()))?;

        // Find user
        let user = self.user_repo.find_by_user_id(&credential.user_id).await?
            .ok_or(FidoError::UserNotFound(credential.user_id.to_string()))?;

        // Decode assertion data
        let authenticator_data = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.response.authenticatorData)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid authenticator data: {}", e)))?;

        let client_data_json = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.response.clientDataJSON)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid client data JSON: {}", e)))?;

        let signature = general_purpose::URL_SAFE_NO_PAD
            .decode(&request.response.signature)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid signature: {}", e)))?;

        // Extract challenge from client data
        let client_data: ClientData = serde_json::from_slice(&client_data_json)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid client data: {}", e)))?;

        // Validate origin
        if client_data.origin.as_str() != get_config().webauthn.rp_origin {
            return Err(FidoError::InvalidOrigin);
        }

        // Validate challenge
        let challenge_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|e| FidoError::InvalidInput(format!("Invalid challenge: {}", e)))?;

        let stored_challenge = self.challenge_repo
            .find_and_consume_challenge(&challenge_bytes)
            .await?;

        if stored_challenge.is_none() {
            return Err(FidoError::InvalidChallenge);
        }

        // Create credential for verification
        let credential_data = CredentialData {
            credential_id: credential.credential_id.clone(),
            public_key: credential.credential_public_key.clone(),
            counter: credential.sign_count as u32,
            user_verified: credential.user_verified,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            transports: credential.transports
                .and_then(|t| serde_json::from_value(t).ok())
                .unwrap_or_default(),
        };

        // Create assertion response
        let assertion_response = AuthenticatorAssertionResponseRaw {
            authenticator_data,
            client_data_json,
            signature,
            user_handle: request.response.userHandle.as_ref()
                .and_then(|uh| general_purpose::URL_SAFE_NO_PAD.decode(uh).ok()),
        };

        let public_key_credential = PublicKeyCredential {
            id: request.id.clone(),
            raw_id: credential_id.clone(),
            response: assertion_response,
            type_: "public-key".to_string(),
            client_extension_results: request.clientExtensionResults.clone(),
            authenticator_attachment: None,
        };

        // Verify assertion
        let auth_result = self.webauthn
            .authenticate_credential(&public_key_credential, &credential_data)
            .map_err(|e| FidoError::WebAuthn(e))?;

        // Update credential
        self.credential_repo
            .update_sign_count(&credential_id, auth_result.counter as i64)
            .await?;

        self.credential_repo
            .update_last_used(&credential_id)
            .await?;

        // Update user last login
        self.user_repo.update_last_login(&user.id).await?;

        Ok(AssertionResultResponse {
            status: "ok".to_string(),
            errorMessage: String::new(),
            userHandle: general_purpose::URL_SAFE_NO_PAD.encode(&user.user_handle),
        })
    }

    fn validate_attestation_request(&self, request: &AttestationOptionsRequest) -> Result<()> {
        if request.username.is_empty() {
            return Err(FidoError::InvalidInput("Username cannot be empty".to_string()));
        }

        if request.displayName.is_empty() {
            return Err(FidoError::InvalidInput("Display name cannot be empty".to_string()));
        }

        if request.username.len() < 3 || request.username.len() > 64 {
            return Err(FidoError::InvalidInput("Username must be 3-64 characters".to_string()));
        }

        if request.displayName.len() > 128 {
            return Err(FidoError::InvalidInput("Display name too long".to_string()));
        }

        Ok(())
    }

    fn generate_challenge(&self) -> String {
        let mut rng = thread_rng();
        let challenge: [u8; 32] = rng.gen();
        general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    }

    fn generate_user_handle(&self) -> Vec<u8> {
        let mut rng = thread_rng();
        let handle: [u8; 64] = rng.gen();
        handle.to_vec()
    }
}

// Request/Response types
#[derive(Debug, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub displayName: String,
    pub attestation: Option<String>,
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticatorAttachment: Option<String>,
    pub requireResidentKey: Option<bool>,
    pub userVerification: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestationOptionsResponse {
    pub status: String,
    pub errorMessage: String,
    pub challenge: String,
    pub rp: RpInfo,
    pub user: UserInfo,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub attestation: String,
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    pub extensions: serde_json::Value,
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
    pub displayName: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Debug, Deserialize)]
pub struct AttestationResultRequest {
    pub id: String,
    pub rawId: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AttestationResponseData,
    pub clientExtensionResults: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct AttestationResponseData {
    pub attestationObject: String,
    pub clientDataJSON: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationResultResponse {
    pub status: String,
    pub errorMessage: String,
    pub credentialId: String,
}

#[derive(Debug, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: Option<String>,
    pub userVerification: Option<String>,
    pub userHandle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AssertionOptionsResponse {
    pub status: String,
    pub errorMessage: String,
    pub challenge: String,
    pub allowCredentials: Vec<AllowCredentials>,
    pub userVerification: String,
    pub timeout: u32,
    pub extensions: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssertionResultRequest {
    pub id: String,
    pub rawId: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AssertionResponseData,
    pub clientExtensionResults: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct AssertionResponseData {
    pub authenticatorData: String,
    pub clientDataJSON: String,
    pub signature: String,
    pub userHandle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AssertionResultResponse {
    pub status: String,
    pub errorMessage: String,
    pub userHandle: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientData {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: Url,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: Option<bool>,
}
```

This implementation guide provides the foundation for building a secure, FIDO2-compliant WebAuthn server. The code emphasizes security, proper error handling, and comprehensive testing capabilities. Each component is designed to be testable and maintainable while following Rust best practices and FIDO2 specification requirements.