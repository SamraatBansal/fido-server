# FIDO2/WebAuthn Implementation Plan

## Project Overview

This implementation plan provides a structured approach to building a FIDO2/WebAuthn Relying Party Server in Rust with comprehensive testing, security-first design, and FIDO Alliance compliance.

## 1. Project Structure Implementation

### 1.1 Directory Structure Creation

```
fido-server/
├── Cargo.toml                    # Project configuration
├── README.md                     # Project documentation
├── .env.example                  # Environment variables template
├── docker-compose.yml            # Development environment
├── Dockerfile                    # Container configuration
├── rustfmt.toml                  # Code formatting rules
├── clippy.toml                   # Linting configuration
├── .github/                      # CI/CD configuration
│   └── workflows/
│       ├── ci.yml                # Continuous integration
│       └── security.yml          # Security scanning
├── migrations/                   # Database migrations
│   ├── 2024-01-01-000001_create_users.sql
│   ├── 2024-01-01-000002_create_credentials.sql
│   └── 2024-01-01-000003_create_challenges.sql
├── src/                          # Source code
│   ├── lib.rs                    # Library entry point
│   ├── main.rs                   # Binary entry point
│   ├── config/                   # Configuration management
│   │   ├── mod.rs
│   │   ├── app.rs                # Application configuration
│   │   ├── database.rs           # Database configuration
│   │   └── webauthn.rs           # WebAuthn configuration
│   ├── controllers/              # HTTP request handlers
│   │   ├── mod.rs
│   │   ├── attestation.rs        # Registration endpoints
│   │   ├── assertion.rs          # Authentication endpoints
│   │   ├── management.rs         # Management endpoints
│   │   ├── health.rs             # Health check endpoints
│   │   └── test.rs               # Testing endpoints
│   ├── services/                 # Business logic layer
│   │   ├── mod.rs
│   │   ├── webauthn.rs           # WebAuthn service
│   │   ├── user.rs               # User management service
│   │   ├── credential.rs         # Credential management service
│   │   ├── challenge.rs          # Challenge management service
│   │   └── attestation.rs        # Attestation validation service
│   ├── db/                       # Database layer
│   │   ├── mod.rs
│   │   ├── connection.rs         # Connection pool management
│   │   ├── models.rs             # Data models
│   │   ├── repositories.rs       # Repository pattern implementation
│   │   └── schema.rs             # Database schema definitions
│   ├── middleware/               # HTTP middleware
│   │   ├── mod.rs
│   │   ├── cors.rs               # CORS handling
│   │   ├── security.rs           # Security headers
│   │   ├── rate_limit.rs         # Rate limiting
│   │   ├── logging.rs            # Request logging
│   │   └── auth.rs               # Authentication middleware
│   ├── routes/                   # Route definitions
│   │   ├── mod.rs
│   │   ├── api.rs                # API routes
│   │   ├── admin.rs              # Admin routes
│   │   └── health.rs             # Health routes
│   ├── error/                    # Error handling
│   │   ├── mod.rs
│   │   ├── types.rs              # Error type definitions
│   │   └── handlers.rs           # Error response handlers
│   ├── utils/                    # Utilities
│   │   ├── mod.rs
│   │   ├── crypto.rs             # Cryptographic utilities
│   │   ├── validation.rs         # Input validation
│   │   ├── encoding.rs           # Encoding/decoding utilities
│   │   └── time.rs               # Time utilities
│   └── types/                    # Type definitions
│       ├── mod.rs
│       ├── webauthn.rs           # WebAuthn types
│       ├── api.rs                # API request/response types
│       └── database.rs           # Database types
├── tests/                        # Test files
│   ├── common/                   # Common test utilities
│   │   ├── mod.rs
│   │   ├── fixtures.rs           # Test data fixtures
│   │   ├── mock.rs               # Mock implementations
│   │   └── helpers.rs            # Test helper functions
│   ├── unit/                     # Unit tests
│   │   ├── mod.rs
│   │   ├── services/             # Service unit tests
│   │   ├── controllers/          # Controller unit tests
│   │   ├── db/                   # Database unit tests
│   │   └── utils/                # Utility unit tests
│   ├── integration/              # Integration tests
│   │   ├── mod.rs
│   │   ├── api/                  # API integration tests
│   │   ├── webauthn/             # WebAuthn integration tests
│   │   └── database/             # Database integration tests
│   ├── security/                 # Security tests
│   │   ├── mod.rs
│   │   ├── replay_attacks.rs     # Replay attack tests
│   │   ├── input_validation.rs   # Input validation tests
│   │   └── cryptography.rs       # Cryptographic tests
│   ├── compliance/               # Compliance tests
│   │   ├── mod.rs
│   │   ├── fido2_spec.rs         # FIDO2 specification tests
│   │   └── webauthn_api.rs       # WebAuthn API compliance tests
│   └── performance/              # Performance tests
│       ├── mod.rs
│       ├── load.rs               # Load testing
│       └── stress.rs             # Stress testing
├── docs/                         # Documentation
│   ├── api/                      # API documentation
│   ├── security/                 # Security documentation
│   └── deployment/               # Deployment documentation
└── scripts/                      # Utility scripts
    ├── setup.sh                  # Development setup
    ├── test.sh                   # Test runner
    └── deploy.sh                 # Deployment script
```

## 2. Implementation Phases

### Phase 1: Foundation (Week 1-2)

#### 1.1 Project Setup
- [ ] Create project structure
- [ ] Configure Cargo.toml with dependencies
- [ ] Set up development environment (Docker, PostgreSQL)
- [ ] Configure CI/CD pipeline
- [ ] Set up code formatting and linting

#### 1.2 Core Infrastructure
- [ ] Implement configuration management
- [ ] Set up database connection and migrations
- [ ] Create error handling framework
- [ ] Implement logging infrastructure
- [ ] Set up basic HTTP server with Actix-web

#### 1.3 Database Layer
- [ ] Create database models
- [ ] Implement repository pattern
- [ ] Create migration scripts
- [ ] Set up connection pooling
- [ ] Implement basic CRUD operations

### Phase 2: WebAuthn Core (Week 3-4)

#### 2.1 WebAuthn Service Foundation
- [ ] Implement WebAuthn configuration
- [ ] Create challenge management service
- [ ] Implement RP ID and origin validation
- [ ] Set up cryptographic utilities
- [ ] Create credential data structures

#### 2.2 Registration Flow
- [ ] Implement attestation options generation
- [ ] Create attestation validation service
- [ ] Implement credential storage
- [ ] Add user management integration
- [ ] Create registration endpoints

#### 2.3 Authentication Flow
- [ ] Implement assertion options generation
- [ ] Create assertion validation service
- [ ] Implement signature verification
- [ ] Add counter tracking
- [ ] Create authentication endpoints

### Phase 3: Security & Compliance (Week 5-6)

#### 3.1 Security Implementation
- [ ] Implement replay attack prevention
- [ ] Add rate limiting
- [ ] Implement input validation
- [ ] Add security headers
- [ ] Create audit logging

#### 3.2 Compliance Features
- [ ] Implement attestation statement validation
- [ ] Add metadata statement processing
- [ ] Create compliance testing framework
- [ ] Implement FIDO2 specification checks
- [ ] Add interoperability testing

#### 3.3 Advanced Features
- [ ] Implement credential management
- [ ] Add user management endpoints
- [ ] Create backup/restore functionality
- [ ] Implement credential discovery
- [ ] Add extension support

### Phase 4: Testing & Optimization (Week 7-8)

#### 4.1 Comprehensive Testing
- [ ] Implement unit tests (95%+ coverage)
- [ ] Create integration tests
- [ ] Add security tests
- [ ] Implement compliance tests
- [ ] Create performance tests

#### 4.2 Performance Optimization
- [ ] Optimize database queries
- [ ] Implement caching strategies
- [ ] Add connection pooling optimization
- [ ] Create performance monitoring
- [ ] Implement load balancing

#### 4.3 Production Readiness
- [ ] Add health check endpoints
- [ ] Implement monitoring and alerting
- [ ] Create deployment documentation
- [ ] Add security scanning
- [ ] Prepare for production deployment

## 3. Detailed Implementation Tasks

### 3.1 Configuration Management

#### src/config/app.rs
```rust
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load configuration from environment variables
    }
}
```

#### src/config/webauthn.rs
```rust
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub challenge_timeout_secs: u64,
    pub max_credentials_per_user: u32,
}

impl WebAuthnConfig {
    pub fn to_webauthn_config(&self) -> WebauthnConfig {
        WebauthnConfig::builder()
            .rp_id(&self.rp_id)
            .rp_name(&self.rp_name)
            .build()
    }
}
```

### 3.2 Database Models

#### src/db/models.rs
```rust
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Uuid,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub transports: Option<serde_json::Value>,
    pub user_verification_policy: String,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_value: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
```

### 3.3 WebAuthn Service

#### src/services/webauthn.rs
```rust
use webauthn_rs::prelude::*;
use crate::error::Result;
use crate::types::webauthn::*;

pub struct WebAuthnService {
    webauthn: Webauthn,
    challenge_service: Arc<dyn ChallengeService>,
    credential_service: Arc<dyn CredentialService>,
}

impl WebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        challenge_service: Arc<dyn ChallengeService>,
        credential_service: Arc<dyn CredentialService>,
    ) -> Result<Self> {
        let webauthn = Webauthn::new(config.to_webauthn_config());
        
        Ok(Self {
            webauthn,
            challenge_service,
            credential_service,
        })
    }

    pub async fn generate_attestation_options(
        &self,
        request: AttestationOptionsRequest,
    ) -> Result<AttestationOptionsResponse> {
        // Generate attestation options
        // Store challenge
        // Return response
    }

    pub async fn verify_attestation(
        &self,
        request: AttestationResultRequest,
    ) -> Result<AttestationResultResponse> {
        // Verify attestation
        // Store credential
        // Return response
    }

    pub async fn generate_assertion_options(
        &self,
        request: AssertionOptionsRequest,
    ) -> Result<AssertionOptionsResponse> {
        // Generate assertion options
        // Store challenge
        // Return response
    }

    pub async fn verify_assertion(
        &self,
        request: AssertionResultRequest,
    ) -> Result<AssertionResultResponse> {
        // Verify assertion
        // Update credential
        // Return response
    }
}
```

### 3.4 API Controllers

#### src/controllers/attestation.rs
```rust
use actix_web::{web, HttpResponse, Result};
use crate::services::WebAuthnService;
use crate::types::api::*;

pub struct AttestationController {
    webauthn_service: Arc<WebAuthnService>,
}

impl AttestationController {
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    pub async fn attestation_options(
        &self,
        request: web::Json<AttestationOptionsRequest>,
    ) -> Result<HttpResponse> {
        match self.webauthn_service.generate_attestation_options(request.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => Ok(HttpResponse::BadRequest().json(ErrorResponse::from(e))),
        }
    }

    pub async fn attestation_result(
        &self,
        request: web::Json<AttestationResultRequest>,
    ) -> Result<HttpResponse> {
        match self.webauthn_service.verify_attestation(request.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => Ok(HttpResponse::BadRequest().json(ErrorResponse::from(e))),
        }
    }
}
```

## 4. Testing Strategy Implementation

### 4.1 Unit Test Structure

#### tests/unit/services/webauthn_test.rs
```rust
use crate::services::WebAuthnService;
use crate::test_common::mock::*;
use tokio_test;

#[tokio::test]
async fn test_generate_attestation_options() {
    let mock_challenge_service = Arc::new(MockChallengeService::new());
    let mock_credential_service = Arc::new(MockCredentialService::new());
    
    let service = WebAuthnService::new(
        test_config(),
        mock_challenge_service.clone(),
        mock_credential_service,
    ).unwrap();

    let request = AttestationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        user_verification: "preferred".to_string(),
        attestation: "none".to_string(),
    };

    let result = service.generate_attestation_options(request).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert!(!response.challenge.is_empty());
    assert_eq!(response.rp.id, "example.com");
}

#[tokio::test]
async fn test_challenge_reuse_prevention() {
    // Test that challenges cannot be reused
}

#[tokio::test]
async fn test_rp_id_validation() {
    // Test RP ID validation logic
}
```

### 4.2 Integration Test Structure

#### tests/integration/api/attestation_test.rs
```rust
use actix_web::{test, App};
use crate::routes::configure_routes;
use crate::services::WebAuthnService;

#[actix_rt::test]
async fn test_attestation_flow_integration() {
    let app = test::init_service(
        App::new()
            .configure(configure_routes)
    ).await;

    // Test attestation options
    let req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&serde_json::json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "userVerification": "preferred"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Test attestation result
    // ... complete flow test
}
```

### 4.3 Security Test Structure

#### tests/security/replay_attacks.rs
```rust
use crate::services::WebAuthnService;
use crate::test_common::fixtures::*;

#[tokio::test]
async fn test_challenge_reuse_attack() {
    let service = create_test_service().await;
    
    // Generate challenge
    let options = service.generate_attestation_options(create_test_attestation_request()).await.unwrap();
    let challenge = options.challenge.clone();
    
    // Use challenge successfully
    let result1 = service.verify_attestation(create_test_attestation_result(&challenge)).await;
    assert!(result1.is_ok());
    
    // Attempt to reuse same challenge
    let result2 = service.verify_attestation(create_test_attestation_result(&challenge)).await;
    assert!(result2.is_err());
    assert!(matches!(result2.unwrap_err(), AppError::InvalidChallenge));
}
```

## 5. Development Workflow

### 5.1 Local Development Setup

```bash
# Clone repository
git clone <repository-url>
cd fido-server

# Set up environment
cp .env.example .env
# Edit .env with local configuration

# Start development database
docker-compose up -d postgres

# Run migrations
diesel migration run

# Start development server
cargo run

# Run tests
cargo test

# Run with coverage
cargo tarpaulin --out Html
```

### 5.2 Testing Workflow

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests
cargo test --test '*'

# Run security tests
cargo test security

# Run compliance tests
cargo test compliance

# Run with coverage report
cargo tarpaulin --exclude-files "src/main.rs" --out Html

# Run performance tests
cargo test performance --release
```

### 5.3 CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v3
    
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
    
    - name: Run migrations
      run: |
        cargo install diesel_cli --no-default-features --features postgres
        diesel migration run
    
    - name: Check formatting
      run: cargo fmt -- --check
    
    - name: Run clippy
      run: cargo clippy -- -D warnings
    
    - name: Run tests
      run: cargo test --all-features
    
    - name: Run security audit
      run: cargo audit
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## 6. Deployment Strategy

### 6.1 Container Configuration

```dockerfile
# Dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/fido-server /usr/local/bin/

EXPOSE 8080

CMD ["fido-server"]
```

### 6.2 Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  fido-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/fido_server
      - RP_ID=localhost
      - RP_NAME=Local FIDO Server
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=fido_server
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

This implementation plan provides a comprehensive roadmap for building a secure, compliant, and well-tested FIDO2/WebAuthn Relying Party Server in Rust.