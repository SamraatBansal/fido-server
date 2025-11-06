# FIDO2/WebAuthn Server - Quick Start Implementation Guide

## Prerequisites
- Rust 1.70+ with Cargo
- PostgreSQL 13+ database
- OpenSSL development libraries
- Basic understanding of WebAuthn/FIDO2 protocols

## 1. Project Setup (15 minutes)

### Initialize Cargo Project
```bash
cargo new --lib fido2-webauthn-server
cd fido2-webauthn-server

# Add to Cargo.toml
```

### Essential Dependencies
```toml
[dependencies]
# WebAuthn Implementation
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }

# Web Framework
axum = { version = "0.7", features = ["json", "headers"] }
tower = { version = "0.4", features = ["util", "timeout"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }

# Async Runtime
tokio = { version = "1.0", features = ["full"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Database
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid", "chrono"] }

# Security & Utilities
uuid = { version = "1.0", features = ["v4", "serde"] }
base64 = "0.22"
rand = "0.8"
anyhow = "1.0"
thiserror = "1.0"
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
rstest = "0.18"
mockall = "0.12"
reqwest = { version = "0.11", features = ["json"] }
```

## 2. Database Setup (10 minutes)

### Create Database Schema
```sql
-- migrations/001_initial_schema.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE challenge_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id),
    state_data JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
```

## 3. Core Implementation Structure (30 minutes)

### src/lib.rs - Library Entry Point
```rust
pub mod config;
pub mod handlers;
pub mod services;
pub mod storage;
pub mod security;
pub mod error;

pub use config::AppConfig;
pub use error::{WebAuthnError, Result};

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;

pub fn create_app(config: AppConfig) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/webauthn/register/begin", post(handlers::registration_begin))
        .route("/webauthn/register/complete", post(handlers::registration_complete))
        .route("/webauthn/authenticate/begin", post(handlers::authentication_begin))
        .route("/webauthn/authenticate/complete", post(handlers::authentication_complete))
        .layer(CorsLayer::permissive()) // Configure appropriately for production
        .with_state(config.into_app_state())
}
```

### src/main.rs - Server Entry Point
```rust
use fido2_webauthn_server::{create_app, AppConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::init();
    
    let config = AppConfig::from_env()?;
    let app = create_app(config);
    
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://localhost:3000");
    
    axum::serve(listener, app).await?;
    Ok(())
}
```

## 4. Essential Services Implementation (45 minutes)

### src/services/webauthn_service.rs - Core WebAuthn Logic
```rust
use webauthn_rs::prelude::*;
use uuid::Uuid;
use crate::{storage::UserStorage, error::WebAuthnError, Result};

pub struct WebAuthnService {
    webauthn: Webauthn,
    user_storage: Box<dyn UserStorage>,
}

impl WebAuthnService {
    pub fn new(rp_id: String, rp_origin: Url, user_storage: Box<dyn UserStorage>) -> Result<Self> {
        let rp = RelyingParty::new(rp_id, rp_origin)?;
        let webauthn = WebauthnBuilder::new(&rp)?.build()?;
        
        Ok(Self {
            webauthn,
            user_storage,
        })
    }
    
    pub async fn start_registration(
        &self,
        username: &str,
        display_name: &str,
    ) -> Result<(CreationChallengeResponse, RegistrationState)> {
        // Check if user already exists
        if self.user_storage.find_user_by_username(username).await?.is_some() {
            return Err(WebAuthnError::UserAlreadyExists);
        }
        
        // Generate user ID
        let user_uuid = Uuid::new_v4();
        let user_unique_id = UserId::from(user_uuid.as_bytes().as_slice());
        
        // Create user
        let user = User::new(user_unique_id, username, display_name);
        
        // Generate registration challenge
        let (ccr, rs) = self.webauthn.start_passkey_registration(
            &user,
            None, // No existing credentials to exclude
            None, // Default authenticator selection
            None, // Default attestation preference
        )?;
        
        Ok((ccr, rs))
    }
    
    pub async fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &RegistrationState,
    ) -> Result<()> {
        // Verify the registration
        let sk = self.webauthn.finish_passkey_registration(reg, state)?;
        
        // Store the credential
        self.user_storage.store_credential(sk).await?;
        
        Ok(())
    }
    
    pub async fn start_authentication(
        &self,
        username: Option<&str>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState)> {
        let creds = if let Some(username) = username {
            // User-identified flow
            self.user_storage.get_user_credentials(username).await?
        } else {
            // Usernameless flow - all credentials
            vec![]
        };
        
        let (rcr, as_) = self.webauthn.start_passkey_authentication(&creds)?;
        Ok((rcr, as_))
    }
    
    pub async fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &AuthenticationState,
    ) -> Result<AuthenticationResult> {
        let result = self.webauthn.finish_passkey_authentication(auth, state)?;
        
        // Update credential counter
        self.user_storage.update_credential_counter(&result.cred_id(), result.counter()).await?;
        
        Ok(result)
    }
}
```

## 5. HTTP Handlers Implementation (30 minutes)

### src/handlers/registration.rs
```rust
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use crate::{services::WebAuthnService, error::WebAuthnError, Result};

#[derive(Deserialize)]
pub struct RegistrationBeginRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct RegistrationBeginResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(flatten)]
    pub challenge_response: Option<webauthn_rs::prelude::CreationChallengeResponse>,
}

pub async fn registration_begin(
    State(service): State<WebAuthnService>,
    Json(req): Json<RegistrationBeginRequest>,
) -> Result<Json<RegistrationBeginResponse>> {
    // Input validation
    if req.username.is_empty() || req.username.len() > 255 {
        return Ok(Json(RegistrationBeginResponse {
            status: "failed".to_string(),
            error_message: "Invalid username".to_string(),
            challenge_response: None,
        }));
    }
    
    match service.start_registration(&req.username, &req.display_name).await {
        Ok((challenge, state)) => {
            // Store state in session (implementation needed)
            // session_store.store_registration_state(state).await?;
            
            Ok(Json(RegistrationBeginResponse {
                status: "ok".to_string(),
                error_message: "".to_string(),
                challenge_response: Some(challenge),
            }))
        }
        Err(e) => Ok(Json(RegistrationBeginResponse {
            status: "failed".to_string(),
            error_message: e.to_string(),
            challenge_response: None,
        }))
    }
}

pub async fn registration_complete(
    State(service): State<WebAuthnService>,
    Json(reg): Json<webauthn_rs::prelude::RegisterPublicKeyCredential>,
) -> Result<Json<serde_json::Value>> {
    // Retrieve stored state (implementation needed)
    // let state = session_store.get_registration_state(&challenge).await?;
    
    match service.finish_registration(&reg, &state).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "ok",
            "errorMessage": ""
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "status": "failed", 
            "errorMessage": e.to_string()
        })))
    }
}
```

## 6. Basic Security Implementation (20 minutes)

### src/security/challenge.rs - Challenge Management
```rust
use rand::{RngCore, CryptoRng};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, Duration};
use crate::{error::SecurityError, Result};

pub struct ChallengeManager {
    rng: Box<dyn CryptoRng + RngCore + Send + Sync>,
}

impl ChallengeManager {
    pub fn new() -> Self {
        Self {
            rng: Box::new(rand::thread_rng()),
        }
    }
    
    pub fn generate_challenge(&mut self) -> Vec<u8> {
        let mut challenge = vec![0u8; 32];
        self.rng.fill_bytes(&mut challenge);
        
        // Add timestamp entropy
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        let mut hasher = Sha256::new();
        hasher.update(&challenge);
        hasher.update(&timestamp.to_le_bytes());
        
        hasher.finalize().to_vec()
    }
    
    pub fn is_challenge_valid(&self, challenge: &[u8], max_age: Duration) -> bool {
        // Implementation would check challenge store and expiration
        // This is a simplified version
        challenge.len() >= 32
    }
}
```

## 7. Basic Testing Setup (15 minutes)

### tests/integration/basic_flow_test.rs
```rust
use fido2_webauthn_server::create_app;
use reqwest::Client;
use serde_json::json;

#[tokio::test]
async fn test_registration_flow_basic() {
    // Setup test server
    let config = create_test_config().await;
    let app = create_app(config);
    let server = axum_test::TestServer::new(app).unwrap();
    
    // Test registration begin
    let response = server
        .post("/webauthn/register/begin")
        .json(&json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .await;
    
    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    
    assert_eq!(body["status"], "ok");
    assert!(body["challenge"].is_string());
    assert_eq!(body["rp"]["id"], "localhost");
}

#[tokio::test] 
async fn test_invalid_registration_request() {
    let config = create_test_config().await;
    let app = create_app(config);
    let server = axum_test::TestServer::new(app).unwrap();
    
    // Test with empty username
    let response = server
        .post("/webauthn/register/begin")
        .json(&json!({
            "username": "",
            "displayName": "Test User"
        }))
        .await;
    
    response.assert_status(400);
}

async fn create_test_config() -> fido2_webauthn_server::AppConfig {
    // Return test configuration
    todo!("Implement test config creation")
}
```

## 8. Running and Testing

### Start Development Server
```bash
# Set environment variables
export DATABASE_URL="postgresql://user:password@localhost/webauthn_db"
export RP_ID="localhost"
export RP_ORIGIN="http://localhost:3000"

# Run migrations
sqlx migrate run

# Start server
cargo run
```

### Test with curl
```bash
# Test registration begin
curl -X POST http://localhost:3000/webauthn/register/begin \
  -H "Content-Type: application/json" \
  -d '{"username": "test@example.com", "displayName": "Test User"}'

# Test health check
curl http://localhost:3000/health
```

### Run Tests
```bash
# Unit tests
cargo test --lib

# Integration tests  
cargo test --test integration

# All tests
cargo test
```

## 9. Next Steps for Full Implementation

1. **Complete Session Management**: Implement secure session storage for WebAuthn state
2. **Add Authentication Handlers**: Complete authentication begin/complete endpoints
3. **Implement Storage Layer**: Full PostgreSQL integration with proper error handling
4. **Security Hardening**: Add rate limiting, input validation, and security headers
5. **FIDO Conformance**: Implement full FIDO Alliance conformance test suite
6. **Production Setup**: Add logging, monitoring, and deployment configuration

## 10. Security Checklist

- [ ] HTTPS enforcement in production
- [ ] Proper origin validation
- [ ] Challenge uniqueness and expiration
- [ ] Input validation and sanitization
- [ ] Rate limiting implementation
- [ ] Secure session management
- [ ] Audit logging
- [ ] Error handling (no information disclosure)

This quick start guide provides a working foundation that can be incrementally enhanced following the comprehensive technical specification. Each component should be thoroughly tested before adding complexity.