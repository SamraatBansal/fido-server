# FIDO2/WebAuthn Server Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing the FIDO2/WebAuthn Relying Party Server according to the technical specifications. It follows a test-driven development approach with detailed implementation patterns and best practices.

## 1. Project Setup and Configuration

### 1.1 Initial Project Structure

First, ensure your project follows the specified structure:

```bash
# Create the directory structure
mkdir -p src/{config,controllers,db/{models,repositories},middleware,routes,services,error,utils,schema}
mkdir -p tests/{common,integration}
mkdir -p migrations
```

### 1.2 Core Dependencies Configuration

Update your `Cargo.toml` with the following key dependencies:

```toml
[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"

# FIDO/WebAuthn
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
diesel_migrations = "2.1"
r2d2 = "0.8"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Async Runtime
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

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tokio-test = "0.4"
serial_test = "3.0"
proptest = "1.4"
criterion = "0.5"
```

### 1.3 Configuration Management

Create the configuration structure in `src/config/mod.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub challenge_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub session_timeout_secs: u64,
    pub max_login_attempts: u32,
    pub rate_limit_requests: u32,
    pub rate_limit_window_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv::dotenv().ok();
        
        let config = Config {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                workers: env::var("SERVER_WORKERS")
                    .unwrap_or_else(|_| "4".to_string())
                    .parse()?,
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgresql://localhost/fido_server".to_string()),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()?,
            },
            webauthn: WebAuthnConfig {
                rp_id: env::var("WEBAUTHN_RP_ID")
                    .unwrap_or_else(|_| "localhost".to_string()),
                rp_name: env::var("WEBAUTHN_RP_NAME")
                    .unwrap_or_else(|_| "FIDO Server".to_string()),
                rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
                challenge_timeout_secs: env::var("WEBAUTHN_CHALLENGE_TIMEOUT")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()?,
            },
            security: SecurityConfig {
                session_timeout_secs: env::var("SECURITY_SESSION_TIMEOUT")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()?,
                max_login_attempts: env::var("SECURITY_MAX_LOGIN_ATTEMPTS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()?,
                rate_limit_requests: env::var("SECURITY_RATE_LIMIT_REQUESTS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()?,
                rate_limit_window_secs: env::var("SECURITY_RATE_LIMIT_WINDOW")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
            },
        };
        
        Ok(config)
    }
}
```

## 2. Error Handling Implementation

### 2.1 Application Error Types

Create comprehensive error handling in `src/error/mod.rs`:

```rust
use thiserror::Error;
use actix_web::{HttpResponse, ResponseError};
use serde_json::json;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Database connection error: {0}")]
    DatabaseConnection(#[from] diesel::result::ConnectionError),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebAuthnError),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Rate limited")]
    RateLimited,
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("Invalid username")]
    InvalidUsername,
    
    #[error("Invalid credential format")]
    InvalidCredentialFormat,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Challenge not found")]
    ChallengeNotFound,
    
    #[error("Invalid attestation")]
    InvalidAttestation,
    
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    
    #[error("Invalid sign counter")]
    InvalidSignCounter,
    
    #[error("User verification required")]
    UserVerificationRequired,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Duplicate credential")]
    DuplicateCredential,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let message = self.to_string();
        
        HttpResponse::build(status).json(json!({
            "error": {
                "code": status.as_u16(),
                "message": message
            }
        }))
    }
}

impl AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AppError::Database(_) | AppError::DatabaseConnection(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::WebAuthn(WebAuthnError::InvalidUsername) => {
                actix_web::http::StatusCode::BAD_REQUEST
            }
            AppError::WebAuthn(WebAuthnError::InvalidCredentialFormat) => {
                actix_web::http::StatusCode::BAD_REQUEST
            }
            AppError::WebAuthn(WebAuthnError::InvalidSignature) => {
                actix_web::http::StatusCode::UNAUTHORIZED
            }
            AppError::WebAuthn(WebAuthnError::ChallengeExpired) => {
                actix_web::http::StatusCode::UNAUTHORIZED
            }
            AppError::WebAuthn(WebAuthnError::ChallengeNotFound) => {
                actix_web::http::StatusCode::BAD_REQUEST
            }
            AppError::WebAuthn(WebAuthnError::InvalidAttestation) => {
                actix_web::http::StatusCode::UNAUTHORIZED
            }
            AppError::WebAuthn(WebAuthnError::UnsupportedAlgorithm) => {
                actix_web::http::StatusCode::BAD_REQUEST
            }
            AppError::WebAuthn(WebAuthnError::InvalidSignCounter) => {
                actix_web::http::StatusCode::UNAUTHORIZED
            }
            AppError::WebAuthn(WebAuthnError::UserVerificationRequired) => {
                actix_web::http::StatusCode::UNAUTHORIZED
            }
            AppError::WebAuthn(WebAuthnError::UserNotFound) => {
                actix_web::http::StatusCode::NOT_FOUND
            }
            AppError::WebAuthn(WebAuthnError::CredentialNotFound) => {
                actix_web::http::StatusCode::NOT_FOUND
            }
            AppError::WebAuthn(WebAuthnError::DuplicateCredential) => {
                actix_web::http::StatusCode::CONFLICT
            }
            AppError::Validation(_) => actix_web::http::StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            AppError::Unauthorized(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => actix_web::http::StatusCode::FORBIDDEN,
            AppError::Conflict(_) => actix_web::http::StatusCode::CONFLICT,
            AppError::RateLimited => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            AppError::Internal(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
```

## 3. Database Layer Implementation

### 3.1 Database Models

Create the database models in `src/db/models/mod.rs`:

```rust
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub user_verification: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_used: bool,
}

// Insertable structs
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub user_verification: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge_id: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}
```

### 3.2 Database Schema

Create the schema file in `src/schema/mod.rs`:

```rust
// @generated automatically by Diesel CLI.

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge_id -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        is_used -> Bool,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        credential_public_key -> Bytea,
        attestation_type -> Varchar,
        aaguid -> Nullable<Bytea>,
        sign_count -> Int8,
        transports -> Nullable<Jsonb>,
        created_at -> Timestamp,
        last_used -> Nullable<Timestamp>,
        is_backup_eligible -> Bool,
        is_backed_up -> Bool,
        user_verification -> Bool,
        is_active -> Bool,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_login -> Nullable<Timestamp>,
        is_active -> Bool,
    }
}

diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(challenges -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    challenges,
    credentials,
    users,
);
```

### 3.3 Repository Pattern Implementation

Create the repository layer in `src/db/repositories/mod.rs`:

```rust
use crate::db::models::*;
use crate::error::{AppError, Result};
use chrono::Utc;
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

    pub async fn create(&self, new_user: &NewUser) -> Result<User> {
        let mut conn = self.pool.get()?;
        
        let user = diesel::insert_into(crate::schema::users::table)
            .values(new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)?;
            
        Ok(user)
    }

    pub async fn get_by_id(&self, user_id: &Uuid) -> Result<User> {
        let mut conn = self.pool.get()?;
        
        let user = crate::schema::users::table
            .filter(crate::schema::users::id.eq(user_id))
            .first::<User>(&mut conn)?;
            
        Ok(user)
    }

    pub async fn get_by_username(&self, username: &str) -> Result<User> {
        let mut conn = self.pool.get()?;
        
        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username))
            .first::<User>(&mut conn)?;
            
        Ok(user)
    }

    pub async fn update(&self, user: &User) -> Result<User> {
        let mut conn = self.pool.get()?;
        
        let updated_user = diesel::update(crate::schema::users::table.filter(crate::schema::users::id.eq(&user.id)))
            .set((
                crate::schema::users::username.eq(&user.username),
                crate::schema::users::display_name.eq(&user.display_name),
                crate::schema::users::updated_at.eq(Utc::now()),
                crate::schema::users::last_login.eq(user.last_login),
                crate::schema::users::is_active.eq(user.is_active),
            ))
            .returning(User::as_returning())
            .get_result(&mut conn)?;
            
        Ok(updated_user)
    }

    pub async fn delete(&self, user_id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::delete(crate::schema::users::table.filter(crate::schema::users::id.eq(user_id)))
            .execute(&mut conn)?;
            
        Ok(())
    }
}

pub struct CredentialRepository {
    pool: Arc<DbPool>,
}

impl CredentialRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }

    pub async fn create(&self, new_credential: &NewCredential) -> Result<Credential> {
        let mut conn = self.pool.get()?;
        
        let credential = diesel::insert_into(crate::schema::credentials::table)
            .values(new_credential)
            .returning(Credential::as_returning())
            .get_result(&mut conn)?;
            
        Ok(credential)
    }

    pub async fn get_by_id(&self, credential_id: &Uuid) -> Result<Credential> {
        let mut conn = self.pool.get()?;
        
        let credential = crate::schema::credentials::table
            .filter(crate::schema::credentials::id.eq(credential_id))
            .first::<Credential>(&mut conn)?;
            
        Ok(credential)
    }

    pub async fn get_by_credential_id(&self, credential_id: &[u8]) -> Result<Credential> {
        let mut conn = self.pool.get()?;
        
        let credential = crate::schema::credentials::table
            .filter(crate::schema::credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut conn)?;
            
        Ok(credential)
    }

    pub async fn get_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()?;
        
        let credentials = crate::schema::credentials::table
            .filter(crate::schema::credentials::user_id.eq(user_id))
            .filter(crate::schema::credentials::is_active.eq(true))
            .load::<Credential>(&mut conn)?;
            
        Ok(credentials)
    }

    pub async fn update_sign_counter(&self, credential_id: &[u8], sign_count: i64) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::update(
            crate::schema::credentials::table
                .filter(crate::schema::credentials::credential_id.eq(credential_id))
        )
        .set((
            crate::schema::credentials::sign_count.eq(sign_count),
            crate::schema::credentials::last_used.eq(Utc::now()),
        ))
        .execute(&mut conn)?;
            
        Ok(())
    }

    pub async fn delete(&self, credential_id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::delete(crate::schema::credentials::table.filter(crate::schema::credentials::id.eq(credential_id)))
            .execute(&mut conn)?;
            
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

    pub async fn create(&self, new_challenge: &NewChallenge) -> Result<Challenge> {
        let mut conn = self.pool.get()?;
        
        let challenge = diesel::insert_into(crate::schema::challenges::table)
            .values(new_challenge)
            .returning(Challenge::as_returning())
            .get_result(&mut conn)?;
            
        Ok(challenge)
    }

    pub async fn get_by_challenge_id(&self, challenge_id: &[u8]) -> Result<Challenge> {
        let mut conn = self.pool.get()?;
        
        let challenge = crate::schema::challenges::table
            .filter(crate::schema::challenges::challenge_id.eq(challenge_id))
            .first::<Challenge>(&mut conn)?;
            
        Ok(challenge)
    }

    pub async fn mark_used(&self, challenge_id: &[u8]) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::update(
            crate::schema::challenges::table
                .filter(crate::schema::challenges::challenge_id.eq(challenge_id))
        )
        .set(crate::schema::challenges::is_used.eq(true))
        .execute(&mut conn)?;
            
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut conn = self.pool.get()?;
        
        let deleted_count = diesel::delete(
            crate::schema::challenges::table
                .filter(crate::schema::challenges::expires_at.lt(Utc::now()))
        )
        .execute(&mut conn)?;
            
        Ok(deleted_count)
    }
}
```

## 4. WebAuthn Service Implementation

### 4.1 Core WebAuthn Service

Create the main WebAuthn service in `src/services/webauthn_service.rs`:

```rust
use crate::config::WebAuthnConfig;
use crate::db::repositories::{CredentialRepository, ChallengeRepository, UserRepository};
use crate::error::{AppError, Result, WebAuthnError};
use crate::db::models::{Credential, Challenge, NewCredential, NewChallenge, User};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone)]
pub struct WebAuthnService {
    config: WebAuthnConfig,
    webauthn: Webauthn,
    user_repo: Arc<UserRepository>,
    credential_repo: Arc<CredentialRepository>,
    challenge_repo: Arc<ChallengeRepository>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationBeginResponse {
    pub status: String,
    pub challenge: String,
    pub user: Userinfo,
    pub rp: RelyingParty,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub timeout: u64,
    pub exclude_credentials: Vec<ExcludeCredentials>,
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishResponse {
    pub status: String,
    pub credential_id: String,
    pub user: Userinfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationBeginResponse {
    pub status: String,
    pub challenge: String,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredentials>,
    pub user_verification: String,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishResponse {
    pub status: String,
    pub user: Userinfo,
    pub credential_id: String,
    pub sign_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Userinfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludeCredentials {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<String>,
    pub user_verification: String,
    pub resident_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

impl WebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        user_repo: Arc<UserRepository>,
        credential_repo: Arc<CredentialRepository>,
        challenge_repo: Arc<ChallengeRepository>,
    ) -> Result<Self> {
        let rp = RelyingParty {
            id: config.rp_id.clone(),
            name: config.rp_name.clone(),
            origin: Url::parse(&config.rp_origin)
                .map_err(|e| AppError::Internal(format!("Invalid RP origin: {}", e)))?,
        };

        let webauthn = Webauthn::new(rp);

        Ok(Self {
            config,
            webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
        })
    }

    pub async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
        user_verification: &str,
    ) -> Result<RegistrationBeginResponse> {
        // Validate input
        if username.is_empty() || username.len() > 255 {
            return Err(AppError::WebAuthn(WebAuthnError::InvalidUsername));
        }

        if display_name.is_empty() || display_name.len() > 255 {
            return Err(AppError::Validation("Invalid display name".to_string()));
        }

        // Get or create user
        let user = match self.user_repo.get_by_username(username).await {
            Ok(user) => user,
            Err(_) => {
                // Create new user
                let new_user = crate::db::models::NewUser {
                    username: username.to_string(),
                    display_name: display_name.to_string(),
                    is_active: true,
                };
                self.user_repo.create(&new_user).await?
            }
        };

        // Get existing credentials for exclusion
        let existing_credentials = self.credential_repo.get_by_user_id(&user.id).await?;
        let exclude_credentials: Vec<ExcludeCredentials> = existing_credentials
            .into_iter()
            .map(|cred| ExcludeCredentials {
                cred_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: self.parse_transports(&cred.transports),
            })
            .collect();

        // Generate challenge
        let user_id = user.id.as_bytes().to_vec();
        let user_entity = UserEntity {
            id: user_id,
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        let attestation = AttestationConveyancePreference::Direct;
        let authenticator_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            require_resident_key: false,
            user_verification: UserVerificationPolicy::Required,
        };

        let (challenge, state) = self
            .webauthn
            .generate_challenge_register_options(
                user_entity,
                authenticator_selection,
                attestation,
            )
            .map_err(|e| AppError::WebAuthn(WebAuthnError::InvalidAttestation))?;

        // Store challenge
        let challenge_bytes = challenge.challenge_bytes();
        let new_challenge = NewChallenge {
            challenge_id: challenge_bytes.to_vec(),
            user_id: Some(user.id),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.config.challenge_timeout_secs as i64),
        };

        self.challenge_repo.create(&new_challenge).await?;

        // Build response
        let response = RegistrationBeginResponse {
            status: "ok".to_string(),
            challenge: general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes),
            user: Userinfo {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            rp: RelyingParty {
                id: self.config.rp_id.clone(),
                name: self.config.rp_name.clone(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    cred_type: "public-key".to_string(),
                    alg: -7,  // ES256
                },
                PubKeyCredParams {
                    cred_type: "public-key".to_string(),
                    alg: -257, // RS256
                },
                PubKeyCredParams {
                    cred_type: "public-key".to_string(),
                    alg: -8,   // EdDSA
                },
            ],
            timeout: self.config.challenge_timeout_secs * 1000,
            exclude_credentials,
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: None,
                user_verification: user_verification.to_string(),
                resident_key: "preferred".to_string(),
            },
            attestation: "direct".to_string(),
        };

        Ok(response)
    }

    pub async fn verify_registration_attestation(
        &self,
        challenge: &str,
        attestation: Value,
    ) -> Result<RegistrationFinishResponse> {
        // Decode challenge
        let challenge_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(challenge)
            .map_err(|_| AppError::WebAuthn(WebAuthnError::ChallengeNotFound))?;

        // Get stored challenge
        let stored_challenge = self.challenge_repo.get_by_challenge_id(&challenge_bytes).await?;
        
        if stored_challenge.is_used {
            return Err(AppError::WebAuthn(WebAuthnError::ChallengeExpired));
        }

        if stored_challenge.expires_at < Utc::now() {
            return Err(AppError::WebAuthn(WebAuthnError::ChallengeExpired));
        }

        // Parse attestation
        let attestation_response: RegistrationResponse = serde_json::from_value(attestation)
            .map_err(|_| AppError::WebAuthn(WebAuthnError::InvalidCredentialFormat))?;

        // Verify attestation
        let challenge_string = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let verification_result = self
            .webauthn
            .register_credential(&attestation_response, &challenge_string)
            .map_err(|e| AppError::WebAuthn(WebAuthnError::InvalidAttestation))?;

        // Mark challenge as used
        self.challenge_repo.mark_used(&challenge_bytes).await?;

        // Store credential
        let user_id = stored_challenge.user_id.ok_or_else(|| {
            AppError::WebAuthn(WebAuthnError::UserNotFound)
        })?;

        let new_credential = NewCredential {
            user_id,
            credential_id: verification_result.cred_id.0,
            credential_public_key: verification_result.public_key,
            attestation_type: verification_result.attestation_format.to_string(),
            aaguid: Some(verification_result.aaguid),
            sign_count: verification_result.counter as i64,
            transports: Some(json!(verification_result.transports)),
            is_backup_eligible: verification_result.backup_eligible,
            is_backed_up: verification_result.backup_state,
            user_verification: verification_result.user_verified,
            is_active: true,
        };

        let stored_credential = self.credential_repo.create(&new_credential).await?;

        // Get user for response
        let user = self.user_repo.get_by_id(&user_id).await?;

        Ok(RegistrationFinishResponse {
            status: "ok".to_string(),
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&stored_credential.credential_id),
            user: Userinfo {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
        })
    }

    pub async fn generate_authentication_challenge(
        &self,
        username: &str,
        user_verification: &str,
    ) -> Result<AuthenticationBeginResponse> {
        // Get user
        let user = self.user_repo.get_by_username(username).await?;

        // Get user credentials
        let credentials = self.credential_repo.get_by_user_id(&user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::WebAuthn(WebAuthnError::CredentialNotFound));
        }

        // Generate challenge
        let (challenge, state) = self
            .webauthn
            .generate_challenge_authenticate_options()
            .map_err(|e| AppError::WebAuthn(WebAuthnError::InvalidAttestation))?;

        // Store challenge
        let challenge_bytes = challenge.challenge_bytes();
        let new_challenge = NewChallenge {
            challenge_id: challenge_bytes.to_vec(),
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.config.challenge_timeout_secs as i64),
        };

        self.challenge_repo.create(&new_challenge).await?;

        // Build allow credentials list
        let allow_credentials: Vec<AllowCredentials> = credentials
            .into_iter()
            .map(|cred| AllowCredentials {
                cred_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: self.parse_transports(&cred.transports),
            })
            .collect();

        Ok(AuthenticationBeginResponse {
            status: "ok".to_string(),
            challenge: general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes),
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: user_verification.to_string(),
            timeout: self.config.challenge_timeout_secs * 1000,
        })
    }

    pub async fn verify_authentication_assertion(
        &self,
        challenge: &str,
        assertion: Value,
    ) -> Result<AuthenticationFinishResponse> {
        // Decode challenge
        let challenge_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(challenge)
            .map_err(|_| AppError::WebAuthn(WebAuthnError::ChallengeNotFound))?;

        // Get stored challenge
        let stored_challenge = self.challenge_repo.get_by_challenge_id(&challenge_bytes).await?;
        
        if stored_challenge.is_used {
            return Err(AppError::WebAuthn(WebAuthnError::ChallengeExpired));
        }

        if stored_challenge.expires_at < Utc::now() {
            return Err(AppError::WebAuthn(WebAuthnError::ChallengeExpired));
        }

        // Parse assertion
        let assertion_response: AuthenticationResponse = serde_json::from_value(assertion)
            .map_err(|_| AppError::WebAuthn(WebAuthnError::InvalidCredentialFormat))?;

        // Get credential
        let credential_id = general_purpose::URL_SAFE_NO_PAD
            .decode(&assertion_response.id)
            .map_err(|_| AppError::WebAuthn(WebAuthnError::InvalidCredentialFormat))?;

        let credential = self.credential_repo.get_by_credential_id(&credential_id).await?;

        // Verify assertion
        let challenge_string = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let verification_result = self
            .webauthn
            .authenticate_credential(&assertion_response, &challenge_string)
            .map_err(|e| AppError::WebAuthn(WebAuthnError::InvalidSignature))?;

        // Mark challenge as used
        self.challenge_repo.mark_used(&challenge_bytes).await?;

        // Update credential sign counter
        self.credential_repo
            .update_sign_counter(&credential_id, verification_result.counter as i64)
            .await?;

        // Get user for response
        let user = self.user_repo.get_by_id(&credential.user_id).await?;

        Ok(AuthenticationFinishResponse {
            status: "ok".to_string(),
            user: Userinfo {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&credential_id),
            sign_count: verification_result.counter as i64,
        })
    }

    fn parse_transports(&self, transports: &Option<Value>) -> Option<Vec<String>> {
        transports.as_ref().and_then(|t| {
            t.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
        })
    }
}
```

## 5. API Controllers Implementation

### 5.1 Registration Controller

Create the registration controller in `src/controllers/registration.rs`:

```rust
use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::services::webauthn_service::{WebAuthnService, RegistrationBeginResponse, RegistrationFinishResponse};
use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct RegistrationBeginRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: String,
    pub attestation: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    pub credential: serde_json::Value,
    pub user: crate::services::webauthn_service::Userinfo,
}

pub struct RegistrationController {
    webauthn_service: Arc<WebAuthnService>,
}

impl RegistrationController {
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    pub async fn begin_registration(
        &self,
        req: web::Json<RegistrationBeginRequest>,
    ) -> Result<HttpResponse> {
        let response = self
            .webauthn_service
            .generate_registration_challenge(
                &req.username,
                &req.display_name,
                &req.user_verification,
            )
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    pub async fn finish_registration(
        &self,
        req: web::Json<RegistrationFinishRequest>,
    ) -> Result<HttpResponse> {
        // Extract challenge from credential response
        let client_data = &req.credential["response"]["clientDataJSON"];
        let client_data_str = client_data
            .as_str()
            .ok_or_else(|| AppError::Validation("Invalid client data".to_string()))?;

        let client_data: serde_json::Value = serde_json::from_str(client_data_str)
            .map_err(|_| AppError::Validation("Invalid client data JSON".to_string()))?;

        let challenge = client_data["challenge"]
            .as_str()
            .ok_or_else(|| AppError::Validation("Missing challenge".to_string()))?;

        let response = self
            .webauthn_service
            .verify_registration_attestation(challenge, req.credential.clone())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }
}

// Route handlers
pub async fn begin_registration(
    req: web::Json<RegistrationBeginRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = RegistrationController::new(webauthn_service.get_ref().clone());
    controller.begin_registration(req).await
}

pub async fn finish_registration(
    req: web::Json<RegistrationFinishRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = RegistrationController::new(webauthn_service.get_ref().clone());
    controller.finish_registration(req).await
}
```

### 5.2 Authentication Controller

Create the authentication controller in `src/controllers/authentication.rs`:

```rust
use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::services::webauthn_service::{WebAuthnService, AuthenticationBeginResponse, AuthenticationFinishResponse};
use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct AuthenticationBeginRequest {
    pub username: String,
    pub user_verification: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub credential: serde_json::Value,
}

pub struct AuthenticationController {
    webauthn_service: Arc<WebAuthnService>,
}

impl AuthenticationController {
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    pub async fn begin_authentication(
        &self,
        req: web::Json<AuthenticationBeginRequest>,
    ) -> Result<HttpResponse> {
        let response = self
            .webauthn_service
            .generate_authentication_challenge(
                &req.username,
                &req.user_verification,
            )
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    pub async fn finish_authentication(
        &self,
        req: web::Json<AuthenticationFinishRequest>,
    ) -> Result<HttpResponse> {
        // Extract challenge from credential response
        let client_data = &req.credential["response"]["clientDataJSON"];
        let client_data_str = client_data
            .as_str()
            .ok_or_else(|| AppError::Validation("Invalid client data".to_string()))?;

        let client_data: serde_json::Value = serde_json::from_str(client_data_str)
            .map_err(|_| AppError::Validation("Invalid client data JSON".to_string()))?;

        let challenge = client_data["challenge"]
            .as_str()
            .ok_or_else(|| AppError::Validation("Missing challenge".to_string()))?;

        let response = self
            .webauthn_service
            .verify_authentication_assertion(challenge, req.credential.clone())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }
}

// Route handlers
pub async fn begin_authentication(
    req: web::Json<AuthenticationBeginRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = AuthenticationController::new(webauthn_service.get_ref().clone());
    controller.begin_authentication(req).await
}

pub async fn finish_authentication(
    req: web::Json<AuthenticationFinishRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = AuthenticationController::new(webauthn_service.get_ref().clone());
    controller.finish_authentication(req).await
}
```

## 6. Main Application Setup

### 6.1 Application Factory

Create the main application setup in `src/main.rs`:

```rust
use actix_cors::Cors;
use actix_web::{web, App, HttpServer, middleware};
use std::sync::Arc;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;

mod config;
mod controllers;
mod db;
mod error;
mod middleware;
mod routes;
mod services;
mod utils;
mod schema;

use config::Config;
use db::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use services::webauthn_service::WebAuthnService;
use routes::{configure_routes};

type DbPool = Pool<ConnectionManager<PgConnection>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");

    // Create database connection pool
    let pool = create_db_pool(&config.database);

    // Create repositories
    let user_repo = Arc::new(UserRepository::new(Arc::new(pool.clone())));
    let credential_repo = Arc::new(CredentialRepository::new(Arc::new(pool.clone())));
    let challenge_repo = Arc::new(ChallengeRepository::new(Arc::new(pool.clone())));

    // Create WebAuthn service
    let webauthn_service = Arc::new(
        WebAuthnService::new(
            config.webauthn.clone(),
            user_repo.clone(),
            credential_repo.clone(),
            challenge_repo.clone(),
        )
        .expect("Failed to create WebAuthn service"),
    );

    // Start cleanup task for expired challenges
    let challenge_repo_cleanup = challenge_repo.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval.tick().await;
            if let Err(e) = challenge_repo_cleanup.cleanup_expired().await {
                log::error!("Failed to cleanup expired challenges: {}", e);
            }
        }
    });

    // Create HTTP server
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(web::Data::new(pool.clone()))
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .configure(configure_routes)
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?;

    log::info!("Starting FIDO2/WebAuthn server on {}:{}", 
               config.server.host, config.server.port);

    server.run().await
}

fn create_db_pool(db_config: &config::DatabaseConfig) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(&db_config.url);
    
    Pool::builder()
        .max_size(db_config.max_connections)
        .min_idle(Some(db_config.min_connections))
        .build(manager)
        .expect("Failed to create database connection pool")
}
```

### 6.2 Route Configuration

Create the route configuration in `src/routes/mod.rs`:

```rust
use actix_web::web;

use crate::controllers::{
    registration::{begin_registration, finish_registration},
    authentication::{begin_authentication, finish_authentication},
};

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webauthn")
            .route("/register/begin", web::post().to(begin_registration))
            .route("/register/finish", web::post().to(finish_registration))
            .route("/authenticate/begin", web::post().to(begin_authentication))
            .route("/authenticate/finish", web::post().to(finish_authentication))
    )
    .route("/health", web::get().to(health_check));
}

async fn health_check() -> &'static str {
    "OK"
}
```

## 7. Testing Implementation

### 7.1 Test Utilities

Create test utilities in `tests/common/mod.rs`:

```rust
use actix_web::{test, App};
use std::sync::Arc;
use uuid::Uuid;
use crate::config::{Config, WebAuthnConfig};
use crate::db::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use crate::services::webauthn_service::WebAuthnService;

pub fn create_test_config() -> Config {
    Config {
        server: crate::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: 1,
        },
        database: crate::config::DatabaseConfig {
            url: "postgresql://postgres:postgres@localhost:5432/test_fido".to_string(),
            max_connections: 5,
            min_connections: 1,
        },
        webauthn: WebAuthnConfig {
            rp_id: "localhost".to_string(),
            rp_name: "Test FIDO Server".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            challenge_timeout_secs: 300,
        },
        security: crate::config::SecurityConfig {
            session_timeout_secs: 3600,
            max_login_attempts: 5,
            rate_limit_requests: 100,
            rate_limit_window_secs: 60,
        },
    }
}

pub async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let config = create_test_config();
    let pool = create_test_db_pool(&config.database);
    
    let user_repo = Arc::new(UserRepository::new(Arc::new(pool.clone())));
    let credential_repo = Arc::new(CredentialRepository::new(Arc::new(pool.clone())));
    let challenge_repo = Arc::new(ChallengeRepository::new(Arc::new(pool.clone())));
    
    let webauthn_service = Arc::new(
        WebAuthnService::new(
            config.webauthn.clone(),
            user_repo.clone(),
            credential_repo.clone(),
            challenge_repo.clone(),
        )
        .unwrap(),
    );

    test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(webauthn_service))
            .app_data(web::Data::new(pool))
            .configure(crate::routes::configure_routes)
    )
    .await
}

pub fn create_test_db_pool(db_config: &crate::config::DatabaseConfig) -> crate::DbPool {
    use diesel::r2d2::{ConnectionManager, Pool};
    
    let manager = ConnectionManager::<diesel::PgConnection>::new(&db_config.url);
    Pool::builder()
        .max_size(db_config.max_connections)
        .min_idle(Some(db_config.min_connections))
        .build(manager)
        .expect("Failed to create test database connection pool")
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

pub fn base64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn create_test_user() -> crate::db::models::User {
    crate::db::models::User {
        id: Uuid::new_v4(),
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: None,
        is_active: true,
    }
}

pub fn create_test_credential() -> crate::db::models::Credential {
    crate::db::models::Credential {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        credential_id: generate_random_bytes(32),
        credential_public_key: generate_random_bytes(32),
        attestation_type: "packed".to_string(),
        aaguid: Some(generate_random_bytes(16)),
        sign_count: 0,
        transports: Some(serde_json::json!(["internal"])),
        created_at: chrono::Utc::now(),
        last_used: None,
        is_backup_eligible: false,
        is_backed_up: false,
        user_verification: true,
        is_active: true,
    }
}
```

This implementation guide provides a comprehensive foundation for building the FIDO2/WebAuthn Relying Party Server. The code follows security best practices, implements proper error handling, and is structured for comprehensive testing. Each component is designed to be testable and maintainable while ensuring FIDO2 compliance.