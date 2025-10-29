# FIDO2/WebAuthn Server - Implementation Plan

## Overview

This document provides a detailed implementation plan for the FIDO2/WebAuthn Relying Party Server, including project structure, development phases, and specific implementation tasks.

## 1. Project Structure Implementation

### 1.1 Directory Structure Creation
```bash
# Create comprehensive directory structure
mkdir -p src/{config,controllers,services,models,db,middleware,routes,error,utils}
mkdir -p src/db/migrations
mkdir -p tests/{integration,unit,compliance,fixtures}
mkdir -p tests/unit/{services,models,utils}
mkdir -p docs/{api,security,deployment}
mkdir -p scripts/{setup,testing,deployment}
```

### 1.2 Core Files Implementation

#### src/lib.rs - Library Entry Point
```rust
//! FIDO2/WebAuthn Relying Party Server
//! 
//! A secure, compliant WebAuthn server implementation in Rust.

pub mod config;
pub mod controllers;
pub mod services;
pub mod models;
pub mod db;
pub mod middleware;
pub mod routes;
pub mod error;
pub mod utils;

pub use error::{FidoError, FidoResult};
pub use config::FidoConfig;

/// Server version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration
pub fn default_config() -> FidoConfig {
    FidoConfig::default()
}
```

#### src/main.rs - Binary Entry Point
```rust
use actix_web::{App, HttpServer, middleware};
use fido_server::{config::FidoConfig, routes, middleware::cors::CorsMiddleware};
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let config = FidoConfig::from_env().expect("Failed to load configuration");
    
    log::info!("Starting FIDO2/WebAuthn Server v{}", fido_server::VERSION);
    
    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .wrap(middleware::Logger::default())
            .wrap(CorsMiddleware::new())
            .configure(routes::configure)
    })
    .bind(format!("{}:{}", config.host, config.port))?
    .run()
    .await
}
```

## 2. Configuration Module Implementation

### 2.1 src/config/mod.rs
```rust
pub mod webauthn;
pub mod database;

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidoConfig {
    pub host: String,
    pub port: u16,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub require_https: bool,
    pub allowed_origins: Vec<String>,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub registration: u32,
    pub authentication: u32,
    pub user_management: u32,
}

impl FidoConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(FidoConfig {
            host: env::var("FIDO_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("FIDO_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "20".to_string())
                    .parse()?,
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()?,
            },
            webauthn: WebAuthnConfig::from_env()?,
            security: SecurityConfig::from_env()?,
        })
    }
}

impl Default for FidoConfig {
    fn default() -> Self {
        FidoConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database: DatabaseConfig {
                url: "postgresql://localhost/fido_server".to_string(),
                max_connections: 20,
                min_connections: 5,
            },
            webauthn: WebAuthnConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}
```

### 2.2 src/config/webauthn.rs
```rust
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub challenge_timeout: u64,
    pub attestation: AttestationConveyancePreference,
    pub user_verification: UserVerificationPolicy,
}

impl WebAuthnConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(WebAuthnConfig {
            rp_name: env::var("WEBAUTHN_RP_NAME")
                .unwrap_or_else(|_| "FIDO Test Server".to_string()),
            rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "https://localhost:8443".to_string()),
            challenge_timeout: env::var("WEBAUTHN_CHALLENGE_TIMEOUT")
                .unwrap_or_else(|_| "300".to_string())
                .parse()?,
            attestation: AttestationConveyancePreference::None,
            user_verification: UserVerificationPolicy::Preferred,
        })
    }
    
    pub fn to_webauthn_config(&self) -> WebauthnConfig {
        WebauthnConfigBuilder::new(&self.rp_name, &self.rp_id, &self.rp_origin)
            .build()
    }
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        WebAuthnConfig {
            rp_name: "FIDO Test Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "https://localhost:8443".to_string(),
            challenge_timeout: 300,
            attestation: AttestationConveyancePreference::None,
            user_verification: UserVerificationPolicy::Preferred,
        }
    }
}
```

## 3. Error Handling Implementation

### 3.1 src/error/mod.rs
```rust
pub mod types;
pub mod handlers;

pub use types::*;
pub use handlers::*;

use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FidoError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Challenge already used")]
    ChallengeUsed,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Duplicate username")]
    DuplicateUsername,
    
    #[error("Duplicate credential")]
    DuplicateCredential,
    
    #[error("Invalid attestation")]
    InvalidAttestation,
    
    #[error("Invalid assertion")]
    InvalidAssertion,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Internal server error")]
    InternalError,
}

impl ResponseError for FidoError {
    fn error_response(&self) -> HttpResponse {
        match self {
            FidoError::InvalidRequest(msg) => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: msg.clone(),
                    error_code: Some("INVALID_REQUEST".to_string()),
                })
            }
            FidoError::ChallengeExpired => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Challenge has expired".to_string(),
                    error_code: Some("CHALLENGE_EXPIRED".to_string()),
                })
            }
            FidoError::ChallengeUsed => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Challenge has already been used".to_string(),
                    error_code: Some("CHALLENGE_USED".to_string()),
                })
            }
            FidoError::UserNotFound => {
                HttpResponse::NotFound().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "User not found".to_string(),
                    error_code: Some("USER_NOT_FOUND".to_string()),
                })
            }
            FidoError::CredentialNotFound => {
                HttpResponse::NotFound().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Credential not found".to_string(),
                    error_code: Some("CREDENTIAL_NOT_FOUND".to_string()),
                })
            }
            FidoError::DuplicateUsername => {
                HttpResponse::Conflict().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Username already exists".to_string(),
                    error_code: Some("DUPLICATE_USERNAME".to_string()),
                })
            }
            FidoError::DuplicateCredential => {
                HttpResponse::Conflict().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Credential already exists".to_string(),
                    error_code: Some("DUPLICATE_CREDENTIAL".to_string()),
                })
            }
            FidoError::InvalidAttestation => {
                HttpResponse::UnprocessableEntity().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Invalid attestation data".to_string(),
                    error_code: Some("INVALID_ATTESTATION".to_string()),
                })
            }
            FidoError::InvalidAssertion => {
                HttpResponse::UnprocessableEntity().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Invalid assertion data".to_string(),
                    error_code: Some("INVALID_ASSERTION".to_string()),
                })
            }
            FidoError::RateLimitExceeded => {
                HttpResponse::TooManyRequests().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Rate limit exceeded".to_string(),
                    error_code: Some("RATE_LIMIT_EXCEEDED".to_string()),
                })
            }
            _ => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: "Internal server error".to_string(),
                    error_code: Some("INTERNAL_ERROR".to_string()),
                })
            }
        }
    }
}

pub type FidoResult<T> = Result<T, FidoError>;
```

### 3.2 src/error/types.rs
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error_message: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessResponse<T> {
    pub status: String,
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> SuccessResponse<T> {
    pub fn new(data: T) -> Self {
        SuccessResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            data: Some(data),
        }
    }
    
    pub fn empty() -> Self {
        SuccessResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            data: None,
        }
    }
}
```

## 4. Database Implementation

### 4.1 src/db/mod.rs
```rust
pub mod connection;
pub mod models;
pub mod queries;
pub mod migrations;

pub use connection::*;
pub use models::*;
pub use queries::*;

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use std::env;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

pub fn establish_connection_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    Pool::builder()
        .max_size(20)
        .min_idle(Some(5))
        .build(manager)
        .expect("Failed to create connection pool")
}
```

### 4.2 src/db/models.rs
```rust
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub is_used: bool,
}

#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}
```

### 4.3 Database Schema (src/db/schema.rs)
```rust
// Generated by diesel CLI
diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Bool,
    }
}

diesel::table! {
    credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        credential_id -> Bytea,
        public_key -> Bytea,
        attestation_format -> Varchar,
        aaguid -> Nullable<Bytea>,
        sign_count -> Int8,
        user_verified -> Bool,
        backup_eligible -> Bool,
        backup_state -> Bool,
        transports -> Nullable<Jsonb>,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
        is_active -> Bool,
    }
}

diesel::table! {
    challenges (id) {
        id -> Uuid,
        challenge -> Bytea,
        user_id -> Nullable<Uuid>,
        challenge_type -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        used_at -> Nullable<Timestamp>,
        is_used -> Bool,
    }
}

diesel::joinable!(credentials -> users (user_id));
diesel::joinable!(challenges -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    credentials,
    challenges,
);
```

## 5. Services Implementation

### 5.1 src/services/mod.rs
```rust
pub mod webauthn;
pub mod user;
pub mod credential;
pub mod challenge;

pub use webauthn::*;
pub use user::*;
pub use credential::*;
pub use challenge::*;

use crate::db::DbPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct Services {
    pub webauthn: Arc<WebAuthnService>,
    pub user: Arc<UserService>,
    pub credential: Arc<CredentialService>,
    pub challenge: Arc<ChallengeService>,
}

impl Services {
    pub fn new(pool: DbPool) -> Self {
        Services {
            webauthn: Arc::new(WebAuthnService::new()),
            user: Arc::new(UserService::new(pool.clone())),
            credential: Arc::new(CredentialService::new(pool.clone())),
            challenge: Arc::new(ChallengeService::new(pool)),
        }
    }
}
```

### 5.2 src/services/webauthn.rs
```rust
use crate::config::WebAuthnConfig;
use crate::error::{FidoError, FidoResult};
use webauthn_rs::prelude::*;
use base64::Engine as _;

pub struct WebAuthnService {
    webauthn: Webauthn,
}

impl WebAuthnService {
    pub fn new() -> Self {
        let config = WebAuthnConfig::default();
        let webauthn_config = config.to_webauthn_config();
        
        WebAuthnService {
            webauthn: Webauthn::new(webauthn_config),
        }
    }
    
    pub fn generate_challenge(&self) -> FidoResult<Challenge> {
        self.webauthn
            .generate_challenge()
            .map_err(FidoError::WebAuthn)
    }
    
    pub fn begin_registration(
        &self,
        user: &UserIdentity,
        challenge: &Challenge,
        exclude_credentials: &[PublicKeyCredentialDescriptor],
    ) -> FidoResult<CreationChallengeResponse> {
        let mut cc = CreationChallengeResponse::new(challenge.clone());
        
        // Set user information
        cc.user = User::from(user);
        
        // Set excluded credentials
        cc.exclude_credentials = exclude_credentials.to_vec();
        
        // Set public key parameters
        cc.pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
                type_: PublicKeyCredentialType::PublicKey,
            },
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::RS256,
                type_: PublicKeyCredentialType::PublicKey,
            },
        ];
        
        // Set timeout
        cc.timeout = Some(60000);
        
        Ok(cc)
    }
    
    pub fn finish_registration(
        &self,
        registration: &PublicKeyCredential,
        challenge: &Challenge,
    ) -> FidoResult<AuthenticatorAttestationResponseRaw> {
        self.webauthn
            .register_credential(registration, challenge)
            .map_err(FidoError::WebAuthn)
    }
    
    pub fn begin_authentication(
        &self,
        challenge: &Challenge,
        allow_credentials: &[PublicKeyCredentialDescriptor],
    ) -> FidoResult<RequestChallengeResponse> {
        let mut rc = RequestChallengeResponse::new(challenge.clone());
        
        // Set allowed credentials
        rc.allow_credentials = allow_credentials.to_vec();
        
        // Set user verification
        rc.user_verification = UserVerificationPolicy::Preferred;
        
        // Set timeout
        rc.timeout = Some(60000);
        
        Ok(rc)
    }
    
    pub fn finish_authentication(
        &self,
        authentication: &PublicKeyCredential,
        challenge: &Challenge,
        credential: &AuthenticatorAttestationResponseRaw,
    ) -> FidoResult<AuthenticationResult> {
        self.webauthn
            .authenticate_credential(authentication, challenge, credential)
            .map_err(FidoError::WebAuthn)
    }
}

impl Default for WebAuthnService {
    fn default() -> Self {
        Self::new()
    }
}
```

## 6. Development Phases

### Phase 1: Infrastructure Setup (Week 1)
- [ ] Create project structure
- [ ] Set up database schema
- [ ] Implement configuration management
- [ ] Set up error handling
- [ ] Create basic logging
- [ ] Set up CI/CD pipeline

### Phase 2: Core Services (Week 2)
- [ ] Implement WebAuthn service
- [ ] Implement user service
- [ ] Implement credential service
- [ ] Implement challenge service
- [ ] Create database migrations
- [ ] Write unit tests for services

### Phase 3: API Controllers (Week 3)
- [ ] Implement registration controller
- [ ] Implement authentication controller
- [ ] Implement user management controller
- [ ] Implement health check controller
- [ ] Add input validation
- [ ] Write integration tests

### Phase 4: Security & Middleware (Week 4)
- [ ] Implement CORS middleware
- [ ] Implement rate limiting
- [ ] Add security headers
- [ ] Implement TLS enforcement
- [ ] Add request logging
- [ ] Write security tests

### Phase 5: Testing & Documentation (Week 5)
- [ ] Complete test coverage (95%+)
- [ ] Implement compliance tests
- [ ] Performance testing
- [ ] API documentation
- [ ] Deployment documentation
- [ ] Security audit preparation

## 7. Testing Strategy Implementation

### 7.1 Unit Test Structure
```rust
// tests/unit/services/webauthn_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::WebAuthnService;
    
    #[test]
    fn test_generate_challenge() {
        let service = WebAuthnService::new();
        let challenge = service.generate_challenge().unwrap();
        
        assert!(challenge.as_ref().len() >= 16);
    }
    
    #[test]
    fn test_challenge_uniqueness() {
        let service = WebAuthnService::new();
        let challenges: Vec<_> = (0..100)
            .map(|_| service.generate_challenge().unwrap())
            .collect();
        
        let unique_challenges: std::collections::HashSet<_> = 
            challenges.iter().collect();
        
        assert_eq!(unique_challenges.len(), challenges.len());
    }
}
```

### 7.2 Integration Test Structure
```rust
// tests/integration/api_test.rs
#[actix_web::test]
async fn test_registration_flow() {
    let app = test::init_service(
        App::new().configure(routes::configure)
    ).await;
    
    // Test registration begin
    let req = test::TestRequest::post()
        .uri("/webauthn/register/begin")
        .set_json(json!({
            "username": "testuser",
            "displayName": "Test User"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    // Test registration complete
    // ... implementation
}
```

## 8. Deployment Configuration

### 8.1 Docker Configuration
```dockerfile
# Dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/fido-server /usr/local/bin/

EXPOSE 8080
CMD ["fido-server"]
```

### 8.2 Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  fido-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://fido:password@postgres:5432/fido_db
      - FIDO_HOST=0.0.0.0
      - FIDO_PORT=8080
    depends_on:
      - postgres
    volumes:
      - ./config:/app/config

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=fido_db
      - POSTGRES_USER=fido
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

This implementation plan provides a comprehensive roadmap for building a secure, compliant FIDO2/WebAuthn server with extensive testing coverage and production-ready deployment configuration.