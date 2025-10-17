# FIDO2/WebAuthn Implementation Guide

## Overview

This implementation guide provides a step-by-step approach to building a secure, compliant FIDO2/WebAuthn Relying Party Server in Rust. The guide follows the technical specifications, security requirements, and testing plans outlined in the previous documents.

## 1. Project Setup and Configuration

### 1.1 Initial Project Structure

```bash
# Create the project structure
mkdir -p src/{config,controllers,services,db,middleware,routes,error,utils}
mkdir -p tests/{unit,integration,security,performance}
mkdir -p migrations
mkdir -p docs
mkdir -p scripts

# Initialize Rust project
cargo init --name fido-server
```

### 1.2 Dependencies Configuration

Update `Cargo.toml` with all required dependencies:

```toml
[package]
name = "fido-server"
version = "0.1.0"
edition = "2021"
authors = ["FIDO Server Team"]
license = "MIT"
description = "FIDO2/WebAuthn Relying Party Server"

[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"
actix-http = "3.9"

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

# Async Runtime
tokio = { version = "1.40", features = ["full"] }
futures = "0.3"

# Cryptography
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }
rand = "0.8"
sha2 = "0.10"
aes-gcm = "0.10"
argon2 = "0.5"

# Configuration
config = "0.14"
dotenv = "0.15"

# Logging
log = "0.4"
env_logger = "0.11"
tracing = "0.1"
tracing-subscriber = "0.3"

# Error Handling
thiserror = "1.0"
anyhow = "1.0"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Validation
validator = { version = "0.18", features = ["derive"] }
regex = "1.10"

# HTTP Client (for webhooks)
reqwest = { version = "0.12", features = ["json"] }

# Metrics
prometheus = "0.13"

# Security
ring = "0.17"
constant_time_eq = "0.3"

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tempfile = "3.10"
wiremock = "0.6"
criterion = "0.5"
proptest = "1.5"

[profile.dev]
opt-level = 0
debug = true

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### 1.3 Configuration Setup

Create `config/default.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4
keep_alive = 75
max_connection_rate = 256

[database]
url = "postgres://fido_user:password@localhost/fido_db"
max_connections = 10
min_connections = 1
connection_timeout = 30
idle_timeout = 600

[webauthn]
rp_id = "localhost"
rp_name = "FIDO2 Test Service"
rp_origin = "http://localhost:8080"
challenge_timeout = 300
max_credentials_per_user = 10

[security]
rate_limit_enabled = true
rate_limit_requests = 100
rate_limit_window = 60
cors_origins = ["http://localhost:3000"]
hsts_enabled = true
hsts_max_age = 31536000

[logging]
level = "info"
format = "json"
output = "stdout"

[monitoring]
metrics_enabled = true
metrics_port = 9090
health_check_interval = 30
```

## 2. Core Implementation

### 2.1 Configuration Module

Create `src/config/mod.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub keep_alive: u64,
    pub max_connection_rate: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub challenge_timeout: u64,
    pub max_credentials_per_user: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub rate_limit_enabled: bool,
    pub rate_limit_requests: u32,
    pub rate_limit_window: u64,
    pub cors_origins: Vec<String>,
    pub hsts_enabled: bool,
    pub hsts_max_age: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub metrics_port: u16,
    pub health_check_interval: u64,
}

impl Config {
    pub fn load() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("config/default"))
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("FIDO"))
            .build()?;

        settings.try_deserialize()
    }

    pub fn database_url(&self) -> &str {
        &self.database.url
    }

    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    pub fn challenge_timeout(&self) -> Duration {
        Duration::from_secs(self.webauthn.challenge_timeout)
    }
}
```

### 2.2 Error Handling Module

Create `src/error/mod.rs`:

```rust
use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;
use validator::ValidationErrors;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationErrors),
    
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Internal server error")]
    InternalError,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error: ErrorDetail,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let (status, error_code, message) = match self {
            AppError::Validation(_) => (
                HttpResponse::BadRequest(),
                "VALIDATION_ERROR",
                "Invalid request parameters",
            ),
            AppError::InvalidRequest(_) => (
                HttpResponse::BadRequest(),
                "INVALID_REQUEST",
                &self.to_string(),
            ),
            AppError::AuthenticationFailed => (
                HttpResponse::Unauthorized(),
                "AUTHENTICATION_FAILED",
                "Authentication failed",
            ),
            AppError::UserNotFound => (
                HttpResponse::NotFound(),
                "USER_NOT_FOUND",
                "User not found",
            ),
            AppError::CredentialNotFound => (
                HttpResponse::NotFound(),
                "CREDENTIAL_NOT_FOUND",
                "Credential not found",
            ),
            AppError::InvalidChallenge => (
                HttpResponse::BadRequest(),
                "INVALID_CHALLENGE",
                "Invalid or expired challenge",
            ),
            AppError::RateLimitExceeded => (
                HttpResponse::TooManyRequests(),
                "RATE_LIMIT_EXCEEDED",
                "Rate limit exceeded",
            ),
            _ => (
                HttpResponse::InternalServerError(),
                "INTERNAL_ERROR",
                "Internal server error",
            ),
        };

        HttpResponse::build(status.status()).json(ErrorResponse {
            status: "error".to_string(),
            error: ErrorDetail {
                code: error_code.to_string(),
                message: message.to_string(),
                details: None,
            },
            timestamp: chrono::Utc::now(),
        })
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
```

### 2.3 Database Models

Create `src/db/models.rs`:

```rust
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::{users, credentials, challenges};

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id_encrypted: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub user_verification_method: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: String,
    pub transports: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id_encrypted: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub user_verification_method: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_type: String,
    pub transports: Vec<String>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: String,
    pub challenge_data: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Insertable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge_id: String,
    pub challenge_data: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}
```

Create `src/schema.rs` (generated by diesel):

```rust
table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Bool,
    }
}

table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id_encrypted -> Bytea,
        credential_public_key -> Bytea,
        aaguid -> Bytea,
        sign_count -> BigInt,
        user_verification_method -> Nullable<Varchar>,
        backup_eligible -> Bool,
        backup_state -> Bool,
        attestation_type -> Varchar,
        transports -> Array<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
        is_active -> Bool,
    }
}

table! {
    challenges (id) {
        id -> Uuid,
        challenge_id -> Varchar,
        challenge_data -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        used_at -> Nullable<Timestamp>,
    }
}

allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);
```

### 2.4 WebAuthn Service Implementation

Create `src/services/webauthn.rs`:

```rust
use std::sync::Arc;
use std::time::Duration;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use rand::RngCore;
use webauthn_rs::prelude::*;
use uuid::Uuid;

use crate::config::WebAuthnConfig;
use crate::db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::error::{AppError, Result};
use crate::utils::crypto::DataEncryption;

pub struct WebAuthnService {
    webauthn: WebAuthn<WebauthnConfig>,
    challenge_repo: Arc<dyn ChallengeRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    user_repo: Arc<dyn UserRepository>,
    encryption: Arc<DataEncryption>,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        challenge_repo: Arc<dyn ChallengeRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        user_repo: Arc<dyn UserRepository>,
        encryption: Arc<DataEncryption>,
    ) -> Result<Self> {
        let rp_id = config.rp_id.clone();
        let rp_name = config.rp_name.clone();
        let rp_origin = config.rp_origin.parse()
            .map_err(|_| AppError::InvalidRequest("Invalid origin".to_string()))?;

        let webauthn_config = WebauthnConfig {
            rp: Rp {
                id: rp_id,
                name: rp_name,
                origin: rp_origin,
            },
            ..Default::default()
        };

        let webauthn = WebAuthn::new(webauthn_config);

        Ok(Self {
            webauthn,
            challenge_repo,
            credential_repo,
            user_repo,
            encryption,
            config,
        })
    }

    pub async fn start_registration(
        &self,
        username: &str,
        display_name: &str,
        user_verification: Option<UserVerificationPolicy>,
        attestation: Option<AttestationConveyancePreference>,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<CreationChallengeResponse> {
        // Get or create user
        let user = self.user_repo.get_by_username(username).await?
            .ok_or_else(|| AppError::UserNotFound)?;

        // Get existing credentials for exclusion
        let existing_creds = if exclude_credentials.is_none() {
            let credentials = self.credential_repo.get_by_user_id(&user.id).await?;
            credentials.into_iter()
                .map(|c| {
                    let credential_id = self.encryption.decrypt(&c.credential_id_encrypted)
                        .map_err(|_| AppError::InternalError)?;
                    Ok(CredentialID::from(credential_id))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            exclude_credentials.unwrap_or_default()
        };

        // Generate registration challenge
        let (ccr, state) = self.webauthn.generate_challenge_register_options(
            user.id.as_bytes(),
            username,
            display_name,
            user_verification,
            attestation,
            Some(existing_creds),
        )?;

        // Store challenge
        let challenge_data = serde_json::to_vec(&state)
            .map_err(|_| AppError::InternalError)?;
        
        let challenge_id = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::seconds(self.config.challenge_timeout as i64);

        self.challenge_repo.store_challenge(
            &challenge_id,
            &challenge_data,
            Some(&user.id),
            "registration",
            expires_at,
        ).await?;

        Ok(ccr)
    }

    pub async fn finish_registration(
        &self,
        username: &str,
        reg_credential: RegisterPublicKeyCredential,
    ) -> Result<AuthenticatorAttestationRawResult> {
        // Get user
        let user = self.user_repo.get_by_username(username).await?
            .ok_or_else(|| AppError::UserNotFound)?;

        // Extract and validate challenge
        let challenge_id = extract_challenge_id(&reg_credential)?;
        let challenge = self.challenge_repo.get_and_remove(&challenge_id).await?
            .ok_or(AppError::InvalidChallenge)?;

        // Verify challenge hasn't expired
        if challenge.expires_at < Utc::now() {
            return Err(AppError::InvalidChallenge);
        }

        // Deserialize challenge state
        let state: RegistrationState = serde_json::from_slice(&challenge.challenge_data)
            .map_err(|_| AppError::InvalidChallenge)?;

        // Verify registration
        let result = self.webauthn.register_credential(&reg_credential, &state)
            .map_err(|_| AppError::InvalidRequest("Registration verification failed".to_string()))?;

        // Encrypt credential ID
        let credential_id_encrypted = self.encryption.encrypt(result.cred_id.as_ref())
            .map_err(|_| AppError::InternalError)?;

        // Store credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id_encrypted,
            credential_public_key: result.cred.public_key().to_vec(),
            aaguid: result.cred.aaguid().to_vec(),
            sign_count: result.cred.counter() as i64,
            user_verification_method: result.cred.user_verification_method().map(|s| s.to_string()),
            backup_eligible: result.cred.backup_eligible(),
            backup_state: result.cred.backup_state(),
            attestation_type: format!("{:?}", result.attestation_type()),
            transports: result.transports.iter().map(|t| t.to_string()).collect(),
        };

        self.credential_repo.create(new_credential).await?;

        Ok(result)
    }

    pub async fn start_authentication(
        &self,
        username: &str,
        user_verification: Option<UserVerificationPolicy>,
    ) -> Result<RequestChallengeResponse> {
        // Get user
        let user = self.user_repo.get_by_username(username).await?
            .ok_or_else(|| AppError::UserNotFound)?;

        // Get user credentials
        let credentials = self.credential_repo.get_by_user_id(&user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::InvalidRequest("No credentials found for user".to_string()));
        }

        // Convert to allow credentials
        let allow_credentials = credentials.into_iter()
            .map(|c| {
                let credential_id = self.encryption.decrypt(&c.credential_id_encrypted)
                    .map_err(|_| AppError::InternalError)?;
                let cred_id = CredentialID::from(credential_id);
                
                let transports = c.transports.into_iter()
                    .filter_map(|t| t.parse().ok())
                    .collect();
                
                Ok(AllowCredentials {
                    type_: "public-key".to_string(),
                    id: cred_id,
                    transports: Some(transports),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Generate authentication challenge
        let (acr, state) = self.webauthn.generate_challenge_authenticate_options(
            allow_credentials,
            user_verification,
        )?;

        // Store challenge
        let challenge_data = serde_json::to_vec(&state)
            .map_err(|_| AppError::InternalError)?;
        
        let challenge_id = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::seconds(self.config.challenge_timeout as i64);

        self.challenge_repo.store_challenge(
            &challenge_id,
            &challenge_data,
            Some(&user.id),
            "authentication",
            expires_at,
        ).await?;

        Ok(acr)
    }

    pub async fn finish_authentication(
        &self,
        auth_credential: PublicKeyCredential,
    ) -> Result<AuthenticatorAssertionRawResult> {
        // Extract and validate challenge
        let challenge_id = extract_challenge_id(&auth_credential)?;
        let challenge = self.challenge_repo.get_and_remove(&challenge_id).await?
            .ok_or(AppError::InvalidChallenge)?;

        // Verify challenge hasn't expired
        if challenge.expires_at < Utc::now() {
            return Err(AppError::InvalidChallenge);
        }

        // Deserialize challenge state
        let state: AuthenticationState = serde_json::from_slice(&challenge.challenge_data)
            .map_err(|_| AppError::InvalidChallenge)?;

        // Get credential for verification
        let credential_id = auth_credential.raw_id.as_ref();
        let credential = self.credential_repo.get_by_credential_id(credential_id).await?
            .ok_or(AppError::CredentialNotFound)?;

        // Decrypt credential ID
        let decrypted_credential_id = self.encryption.decrypt(&credential.credential_id_encrypted)
            .map_err(|_| AppError::InternalError)?;

        // Create credential object for verification
        let cred = PublicKeyCredential {
            id: auth_credential.id.clone(),
            raw_id: decrypted_credential_id.into(),
            response: auth_credential.response,
            type_: auth_credential.type_,
            client_extension_results: auth_credential.client_extension_results,
        };

        // Verify authentication
        let result = self.webauthn.authenticate_credential(&cred, &state)
            .map_err(|_| AppError::AuthenticationFailed)?;

        // Update credential counter and last used
        self.credential_repo.update_usage(
            &credential.id,
            result.auth_data.counter as i64,
            Utc::now(),
        ).await?;

        Ok(result)
    }
}

fn extract_challenge_id(credential: &PublicKeyCredential) -> Result<String> {
    // Extract challenge ID from client data JSON
    let client_data: serde_json::Value = serde_json::from_slice(&credential.response.client_data_json)
        .map_err(|_| AppError::InvalidRequest("Invalid client data".to_string()))?;
    
    let challenge = client_data.get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRequest("Missing challenge".to_string()))?;
    
    // For simplicity, we'll use the challenge itself as the ID
    // In production, you might want to map challenges to IDs
    Ok(challenge.to_string())
}
```

### 2.5 API Controllers

Create `src/controllers/registration.rs`:

```rust
use actix_web::{web, HttpResponse, Result as ActixResult};
use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;

use crate::error::{AppError, Result};
use crate::services::WebAuthnService;
use crate::utils::validation::validate_user_verification;

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationChallengeRequest {
    #[validate(length(min = 1, max = 255))]
    #[validate(email)]
    pub username: String,
    
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    
    #[validate(custom = "validate_user_verification")]
    pub user_verification: Option<String>,
    
    pub attestation: Option<String>,
    
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    
    pub extensions: Option<serde_json::Value>,
    
    pub exclude_credentials: Option<Vec<CredentialDescriptor>>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationChallengeResponse {
    pub status: String,
    pub data: CreationChallengeResponse,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationVerifyRequest {
    #[validate(custom = "validate_credential")]
    pub credential: RegisterPublicKeyCredential,
    
    #[validate(length(min = 1, max = 255))]
    #[validate(email)]
    pub username: String,
    
    pub display_name: Option<String>,
    
    pub user_verification: Option<String>,
    
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationVerifyResponse {
    pub status: String,
    pub data: RegistrationResult,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationResult {
    pub credential_id: String,
    pub credential_type: String,
    pub aaguid: String,
    pub sign_count: u32,
    pub user_verified: bool,
    pub attestation_type: String,
    pub authenticator_info: AuthenticatorInfo,
}

#[derive(Debug, Serialize)]
pub struct AuthenticatorInfo {
    pub aaguid: String,
    pub sign_count: u32,
    pub clone_warning: bool,
}

pub async fn start_registration(
    webauthn_service: web::Data<WebAuthnService>,
    req: web::Json<RegistrationChallengeRequest>,
) -> ActixResult<HttpResponse> {
    // Validate request
    req.validate()
        .map_err(|e| AppError::Validation(e))?;

    // Parse user verification
    let user_verification = req.user_verification.as_ref()
        .and_then(|uv| uv.parse().ok());

    // Parse attestation
    let attestation = req.attestation.as_ref()
        .and_then(|a| a.parse().ok());

    // Parse exclude credentials
    let exclude_credentials = req.exclude_credentials.as_ref()
        .map(|creds| creds.iter().map(|c| c.id.clone()).collect());

    // Start registration
    let challenge_response = webauthn_service.start_registration(
        &req.username,
        &req.display_name,
        user_verification,
        attestation,
        exclude_credentials,
    ).await?;

    Ok(HttpResponse::Ok().json(RegistrationChallengeResponse {
        status: "ok".to_string(),
        data: challenge_response,
        timestamp: chrono::Utc::now(),
    }))
}

pub async fn finish_registration(
    webauthn_service: web::Data<WebAuthnService>,
    req: web::Json<RegistrationVerifyRequest>,
) -> ActixResult<HttpResponse> {
    // Validate request
    req.validate()
        .map_err(|e| AppError::Validation(e))?;

    // Finish registration
    let result = webauthn_service.finish_registration(
        &req.username,
        req.credential.clone(),
    ).await?;

    // Build response
    let registration_result = RegistrationResult {
        credential_id: general_purpose::URL_SAFE_NO_PAD.encode(result.cred_id.as_ref()),
        credential_type: "public-key".to_string(),
        aaguid: general_purpose::URL_SAFE_NO_PAD.encode(result.cred.aaguid()),
        sign_count: result.cred.counter(),
        user_verified: result.user_verified(),
        attestation_type: format!("{:?}", result.attestation_type()),
        authenticator_info: AuthenticatorInfo {
            aaguid: general_purpose::URL_SAFE_NO_PAD.encode(result.cred.aaguid()),
            sign_count: result.cred.counter(),
            clone_warning: false, // TODO: Implement clone detection
        },
    };

    Ok(HttpResponse::Ok().json(RegistrationVerifyResponse {
        status: "ok".to_string(),
        data: registration_result,
        timestamp: chrono::Utc::now(),
    }))
}

// Validation functions
fn validate_credential(credential: &RegisterPublicKeyCredential) -> Result<(), validator::ValidationError> {
    // Validate credential structure
    if credential.id.is_empty() {
        return Err(validator::ValidationError::new("empty_credential_id"));
    }
    
    if credential.type_ != "public-key" {
        return Err(validator::ValidationError::new("invalid_credential_type"));
    }
    
    // Validate response
    if credential.response.attestation_object.is_empty() {
        return Err(validator::ValidationError::new("empty_attestation_object"));
    }
    
    if credential.response.client_data_json.is_empty() {
        return Err(validator::ValidationError::new("empty_client_data_json"));
    }
    
    Ok(())
}
```

## 3. Testing Implementation

### 3.1 Unit Tests

Create `tests/unit/webauthn_service_tests.rs`:

```rust
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use fido_server::services::WebAuthnService;
use fido_server::config::WebAuthnConfig;
use fido_server::utils::crypto::DataEncryption;
use fido_server::db::repositories::{MockChallengeRepository, MockCredentialRepository, MockUserRepository};
use fido_server::db::models::{User, NewUser, Credential, NewCredential, Challenge, NewChallenge};
use fido_server::error::Result;

#[tokio::test]
async fn test_start_registration_success() {
    // Setup mocks
    let mut challenge_repo = MockChallengeRepository::new();
    let mut credential_repo = MockCredentialRepository::new();
    let mut user_repo = MockUserRepository::new();
    
    // Mock user
    let user = User {
        id: Uuid::new_v4(),
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        is_active: true,
    };
    
    user_repo
        .expect_get_by_username()
        .withf(|username| username == "test@example.com")
        .returning(move |_| Ok(Some(user.clone())));
    
    // Mock empty credentials
    credential_repo
        .expect_get_by_user_id()
        .returning(|_| Ok(vec![]));
    
    // Mock challenge storage
    challenge_repo
        .expect_store_challenge()
        .returning(|_, _, _, _, _| Ok(()));
    
    // Create service
    let config = WebAuthnConfig {
        rp_id: "localhost".to_string(),
        rp_name: "Test Service".to_string(),
        rp_origin: "http://localhost:8080".to_string(),
        challenge_timeout: 300,
        max_credentials_per_user: 10,
    };
    
    let encryption = Arc::new(DataEncryption::new("test-key").unwrap());
    let service = WebAuthnService::new(
        config,
        Arc::new(challenge_repo),
        Arc::new(credential_repo),
        Arc::new(user_repo),
        encryption,
    ).unwrap();
    
    // Test
    let result = service.start_registration(
        "test@example.com",
        "Test User",
        Some(UserVerificationPolicy::Required),
        Some(AttestationConveyancePreference::None),
        None,
    ).await;
    
    assert!(result.is_ok());
    
    let challenge_response = result.unwrap();
    assert!(!challenge_response.challenge.is_empty());
    assert_eq!(challenge_response.rp.name, "Test Service");
    assert_eq!(challenge_response.user.name, "test@example.com");
}

#[tokio::test]
async fn test_start_registration_user_not_found() {
    // Setup mocks
    let mut challenge_repo = MockChallengeRepository::new();
    let mut credential_repo = MockCredentialRepository::new();
    let mut user_repo = MockUserRepository::new();
    
    // Mock user not found
    user_repo
        .expect_get_by_username()
        .returning(|_| Ok(None));
    
    // Create service
    let config = WebAuthnConfig {
        rp_id: "localhost".to_string(),
        rp_name: "Test Service".to_string(),
        rp_origin: "http://localhost:8080".to_string(),
        challenge_timeout: 300,
        max_credentials_per_user: 10,
    };
    
    let encryption = Arc::new(DataEncryption::new("test-key").unwrap());
    let service = WebAuthnService::new(
        config,
        Arc::new(challenge_repo),
        Arc::new(credential_repo),
        Arc::new(user_repo),
        encryption,
    ).unwrap();
    
    // Test
    let result = service.start_registration(
        "nonexistent@example.com",
        "Test User",
        None,
        None,
        None,
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), fido_server::error::AppError::UserNotFound));
}

#[tokio::test]
async fn test_challenge_uniqueness() {
    // Test that multiple challenges are unique
    let mut challenges = std::collections::HashSet::new();
    
    for _ in 0..1000 {
        let challenge = generate_test_challenge();
        assert!(!challenges.contains(&challenge), "Duplicate challenge found");
        challenges.insert(challenge);
    }
}

fn generate_test_challenge() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
```

### 3.2 Integration Tests

Create `tests/integration/api_tests.rs`:

```rust
use actix_web::{test, App, http::StatusCode};
use serde_json::json;

use fido_server::configure_app;
use fido_server::config::Config;

#[actix_web::test]
async fn test_registration_flow_complete() {
    // Setup test app
    let config = Config::load().unwrap();
    let app = test::init_service(
        App::new().configure(configure_app(config))
    ).await;
    
    // Step 1: Request registration challenge
    let challenge_request = json!({
        "username": "test@example.com",
        "displayName": "Test User",
        "userVerification": "required",
        "attestation": "none"
    });
    
    let challenge_resp = test::TestRequest::post()
        .uri("/api/v1/registration/challenge")
        .set_json(&challenge_request)
        .send_request(&app)
        .await;
    
    assert_eq!(challenge_resp.status(), StatusCode::OK);
    
    let challenge_body: serde_json::Value = test::read_body_json(challenge_resp).await;
    assert_eq!(challenge_body["status"], "ok");
    assert!(!challenge_body["data"]["challenge"].as_str().unwrap().is_empty());
    
    let challenge = challenge_body["data"]["challenge"].as_str().unwrap();
    
    // Step 2: Complete registration (mock credential)
    let credential_request = json!({
        "credential": {
            "id": "test-credential-id",
            "rawId": "dGVzdC1jcmVkZW50aWFsLWlk",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGZ1YmFjLWNvbnRhaW5lclB1YmxpY0tleQ",
                "clientDataJSON": format!(
                    r#"{{"type":"webauthn.create","challenge":"{}","origin":"http://localhost:8080"}}"#,
                    challenge
                )
            },
            "type": "public-key"
        },
        "username": "test@example.com"
    });
    
    let credential_resp = test::TestRequest::post()
        .uri("/api/v1/registration/verify")
        .set_json(&credential_request)
        .send_request(&app)
        .await;
    
    // This will fail with invalid attestation, but should return proper error
    assert_eq!(credential_resp.status(), StatusCode::BAD_REQUEST);
    
    let error_body: serde_json::Value = test::read_body_json(credential_resp).await;
    assert_eq!(error_body["status"], "error");
    assert!(!error_body["error"]["code"].as_str().unwrap().is_empty());
}

#[actix_web::test]
async fn test_health_check() {
    let config = Config::load().unwrap();
    let app = test::init_service(
        App::new().configure(configure_app(config))
    ).await;
    
    let resp = test::TestRequest::get()
        .uri("/api/v1/health")
        .send_request(&app)
        .await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["data"]["status"], "healthy");
}

#[actix_web::test]
async fn test_rate_limiting() {
    let config = Config::load().unwrap();
    let app = test::init_service(
        App::new().configure(configure_app(config))
    ).await;
    
    // Make multiple rapid requests
    for _ in 0..150 {
        let challenge_request = json!({
            "username": "test@example.com",
            "displayName": "Test User"
        });
        
        let resp = test::TestRequest::post()
            .uri("/api/v1/registration/challenge")
            .set_json(&challenge_request)
            .send_request(&app)
            .await;
        
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            // Rate limit triggered
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["error"]["code"], "RATE_LIMIT_EXCEEDED");
            return;
        }
    }
    
    panic!("Rate limiting was not triggered");
}
```

## 4. Deployment and Operations

### 4.1 Docker Configuration

Create `Dockerfile`:

```dockerfile
# Build stage
FROM rust:1.75 as builder

WORKDIR /app

# Copy source code
COPY . .

# Install diesel CLI
RUN cargo install diesel_cli --no-default-features --features postgres

# Run database migrations
RUN diesel migration run --database-url $DATABASE_URL

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false fido

# Copy binary
COPY --from=builder /app/target/release/fido-server /usr/local/bin/

# Create directories
RUN mkdir -p /app/config /app/logs && chown -R fido:fido /app

# Switch to app user
USER fido

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

# Run the application
CMD ["fido-server"]
```

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  fido-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://fido_user:password@postgres:5432/fido_db
      - FIDO_LOGGING_LEVEL=info
      - FIDO_SECURITY_RATE_LIMIT_ENABLED=true
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=fido_db
      - POSTGRES_USER=fido_user
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fido_user -d fido_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  postgres_data:
  redis_data:
```

### 4.2 CI/CD Pipeline

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    name: Test
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: fido_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        components: rustfmt, clippy
    
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Install diesel CLI
      run: cargo install diesel_cli --no-default-features --features postgres
    
    - name: Run database migrations
      run: diesel migration run --database-url postgres://postgres:postgres@localhost/fido_test
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/fido_test
    
    - name: Check formatting
      run: cargo fmt -- --check
    
    - name: Run clippy
      run: cargo clippy -- -D warnings
    
    - name: Run unit tests
      run: cargo test --lib
    
    - name: Run integration tests
      run: cargo test --test '*'
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/fido_test
    
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml --output-dir ./coverage
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/cobertura.xml

  security:
    name: Security Scan
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run security audit
      run: cargo audit
    
    - name: Run cargo-deny
      uses: EmbarkStudios/cargo-deny-action@v1

  build:
    name: Build
    runs-on: ubuntu-latest
    needs: [test, security]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Build Docker image
      run: docker build -t fido-server:${{ github.sha }} .
    
    - name: Run security scan on Docker image
      run: |
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          -v $PWD:/root/.cache/ aquasec/trivy:latest image \
          --exit-code 0 --no-progress --format table \
          fido-server:${{ github.sha }}

  deploy:
    name: Deploy
    runs-on: ubuntu-latest
    needs: [build]
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment..."
        # Add deployment commands here
    
    - name: Run smoke tests
      run: |
        echo "Running smoke tests..."
        # Add smoke test commands here
```

## 5. Monitoring and Observability

### 5.1 Metrics Configuration

Create `src/monitoring/metrics.rs`:

```rust
use prometheus::{Counter, Histogram, Gauge, Registry, TextEncoder, Encoder};
use actix_web::{web, HttpResponse, Result};
use std::sync::Arc;

pub struct Metrics {
    pub registry: Registry,
    
    // Request metrics
    pub requests_total: Counter,
    pub request_duration: Histogram,
    
    // Authentication metrics
    pub registrations_total: Counter,
    pub authentications_total: Counter,
    pub authentication_failures_total: Counter,
    
    // Database metrics
    pub db_connections_active: Gauge,
    pub db_query_duration: Histogram,
    
    // Security metrics
    pub rate_limit_hits_total: Counter,
    pub security_events_total: Counter,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        
        let requests_total = Counter::new(
            "http_requests_total",
            "Total number of HTTP requests"
        ).unwrap();
        
        let request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds"
            ).buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
        ).unwrap();
        
        let registrations_total = Counter::new(
            "registrations_total",
            "Total number of successful registrations"
        ).unwrap();
        
        let authentications_total = Counter::new(
            "authentications_total",
            "Total number of successful authentications"
        ).unwrap();
        
        let authentication_failures_total = Counter::new(
            "authentication_failures_total",
            "Total number of failed authentications"
        ).unwrap();
        
        let db_connections_active = Gauge::new(
            "db_connections_active",
            "Number of active database connections"
        ).unwrap();
        
        let db_query_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "db_query_duration_seconds",
                "Database query duration in seconds"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
        ).unwrap();
        
        let rate_limit_hits_total = Counter::new(
            "rate_limit_hits_total",
            "Total number of rate limit hits"
        ).unwrap();
        
        let security_events_total = Counter::new(
            "security_events_total",
            "Total number of security events"
        ).unwrap();
        
        registry.register(Box::new(requests_total.clone())).unwrap();
        registry.register(Box::new(request_duration.clone())).unwrap();
        registry.register(Box::new(registrations_total.clone())).unwrap();
        registry.register(Box::new(authentications_total.clone())).unwrap();
        registry.register(Box::new(authentication_failures_total.clone())).unwrap();
        registry.register(Box::new(db_connections_active.clone())).unwrap();
        registry.register(Box::new(db_query_duration.clone())).unwrap();
        registry.register(Box::new(rate_limit_hits_total.clone())).unwrap();
        registry.register(Box::new(security_events_total.clone())).unwrap();
        
        Self {
            registry,
            requests_total,
            request_duration,
            registrations_total,
            authentications_total,
            authentication_failures_total,
            db_connections_active,
            db_query_duration,
            rate_limit_hits_total,
            security_events_total,
        }
    }
}

pub async fn metrics_endpoint(metrics: web::Data<Arc<Metrics>>) -> Result<HttpResponse> {
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer))
}
```

### 5.2 Logging Configuration

Create `src/logging/mod.rs`:

```rust
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use serde_json::json;

pub fn init_logging(level: &str, format: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    
    if format == "json" {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

pub fn log_security_event(
    event_type: &str,
    user_id: Option<&str>,
    ip_address: &str,
    details: &serde_json::Value,
) {
    let event = json!({
        "event_type": event_type,
        "user_id": user_id,
        "ip_address": ip_address,
        "details": details,
        "timestamp": chrono::Utc::now(),
    });
    
    info!(security_event = %serde_json::to_string(&event).unwrap());
}

pub fn log_authentication_attempt(
    username: &str,
    success: bool,
    ip_address: &str,
    user_agent: &str,
) {
    let event = json!({
        "event_type": "authentication_attempt",
        "username": username,
        "success": success,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": chrono::Utc::now(),
    });
    
    if success {
        info!(auth_event = %serde_json::to_string(&event).unwrap());
    } else {
        warn!(auth_event = %serde_json::to_string(&event).unwrap());
    }
}

pub fn log_registration_attempt(
    username: &str,
    success: bool,
    ip_address: &str,
    user_agent: &str,
) {
    let event = json!({
        "event_type": "registration_attempt",
        "username": username,
        "success": success,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": chrono::Utc::now(),
    });
    
    if success {
        info!(reg_event = %serde_json::to_string(&event).unwrap());
    } else {
        warn!(reg_event = %serde_json::to_string(&event).unwrap());
    }
}
```

## 6. Security Hardening

### 6.1 Security Headers Middleware

Create `src/middleware/security.rs`:

```rust
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::middleware::Transform;
use actix_web::HttpMessage;
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;

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
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        
        Box::pin(async move {
            let res = fut.await?;
            
            // Add security headers
            let mut response = res.into_response();
            
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
                "Content-Security-Policy",
                "default-src 'self'".parse().unwrap(),
            );
            
            response.headers_mut().insert(
                "Referrer-Policy",
                "strict-origin-when-cross-origin".parse().unwrap(),
            );
            
            response.headers_mut().insert(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload".parse().unwrap(),
            );
            
            Ok(ServiceResponse::new(res.request().clone(), response))
        })
    }
}
```

### 6.2 Rate Limiting Middleware

Create `src/middleware/rate_limit.rs`:

```rust
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::middleware::Transform;
use actix_web::HttpMessage;
use futures::future::{ok, Ready};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_seconds: u64,
}

pub struct RateLimiter {
    config: RateLimitConfig,
    // In production, use Redis or another distributed store
    storage: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let mut storage = self.storage.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        
        let requests = storage.entry(ip).or_insert_with(Vec::new);
        
        // Remove old requests
        requests.retain(|&timestamp| now.duration_since(timestamp) < window);
        
        // Check if under limit
        if requests.len() < self.config.max_requests as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }
}

pub struct RateLimitMiddleware {
    limiter: Arc<RateLimiter>,
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(config)),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitMiddlewareService {
            service,
            limiter: self.limiter.clone(),
        })
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
    limiter: Arc<RateLimiter>,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = req
            .connection_info()
            .peer_addr()
            .and_then(|addr| addr.parse().ok())
            .unwrap_or_else(|| "127.0.0.1".parse().unwrap());
        
        if !self.limiter.is_allowed(ip) {
            return Box::pin(async {
                Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded"))
            });
        }
        
        let fut = self.service.call(req);
        Box::pin(async move {
            fut.await
        })
    }
}
```

This comprehensive implementation guide provides the foundation for building a secure, compliant, and production-ready FIDO2/WebAuthn Relying Party Server in Rust. The guide covers all aspects from initial setup through deployment and monitoring, ensuring the implementation meets the highest security and compliance standards.