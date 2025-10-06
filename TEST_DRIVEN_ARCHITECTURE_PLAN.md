# Comprehensive Test-Driven Architecture Plan for FIDO2/WebAuthn Relying Party Server

## Executive Summary

Based on the existing foundation, I'll create a comprehensive test-driven architecture that builds upon the current minimal TDD implementation while adding production-ready WebAuthn capabilities, comprehensive testing strategies, and security patterns optimized for automated validation.

## 1. Project Structure & Dependencies (Enhanced)

### 1.1 Cargo.toml Optimizations
The current dependencies are well-chosen. I'll enhance them with:
- **webauthn-rs**: Full utilization with proper configuration
- **Test utilities**: Enhanced mocking and property-based testing
- **Security testing**: Additional security validation tools
- **Performance testing**: Load testing and benchmarking capabilities

### 1.2 Module Organization (Test-First Design)

```
src/
├── lib.rs                    # Library entry point with test exports
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs               # Testable configuration traits
│   ├── database.rs          # Database configuration with validation
│   └── webauthn.rs          # WebAuthn configuration with security defaults
├── controllers/              # HTTP handlers (thin, testable layer)
│   ├── mod.rs
│   ├── registration.rs      # Registration endpoints
│   ├── authentication.rs   # Authentication endpoints
│   ├── credential.rs        # Credential management endpoints
│   └── health.rs            # Health check endpoints
├── services/                 # Business logic (core testable domain)
│   ├── mod.rs
│   ├── fido.rs              # Enhanced FIDO service with WebAuthn integration
│   ├── user.rs              # User management service
│   ├── credential.rs        # Credential operations service
│   ├── attestation.rs       # Attestation verification service
│   ├── session.rs           # Session management service
│   └── security.rs          # Security validation service
├── db/                      # Database layer (mockable repositories)
│   ├── mod.rs
│   ├── connection.rs        # Database connection management
│   ├── models.rs            # Data models with validation
│   └── repositories/        # Repository pattern for testability
│       ├── mod.rs
│       ├── user_repo.rs     # User repository trait + implementations
│       ├── credential_repo.rs # Credential repository trait + implementations
│       └── challenge_repo.rs # Challenge repository trait + implementations
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   ├── rate_limit.rs        # Rate limiting middleware
│   └── security.rs          # Security headers middleware
├── routes/                  # Route definitions
│   ├── mod.rs
│   ├── api.rs               # API routes
│   └── health.rs            # Health check routes
├── error/                   # Error handling
│   ├── mod.rs
│   └── types.rs             # Comprehensive error types
├── utils/                   # Utilities
│   ├── mod.rs
│   ├── crypto.rs            # Cryptographic utilities
│   ├── validation.rs        # Input validation utilities
│   └── testing.rs           # Test utilities and fixtures
└── schema/                  # Database schema
    ├── mod.rs
    └── migrations/          # Database migrations
```

## 2. WebAuthn Integration Architecture

### 2.1 WebAuthn Service Design

```rust
// Core WebAuthn service with dependency injection
pub struct WebAuthnService {
    webauthn: Webauthn,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    challenge_repo: Arc<dyn ChallengeRepository>,
    config: WebAuthnConfig,
    security_service: Arc<dyn SecurityService>,
}

// Trait for easy mocking in tests
#[async_trait]
pub trait WebAuthnServiceTrait {
    async fn start_registration(&self, request: RegistrationRequest) -> Result<CreationChallengeResponse>;
    async fn finish_registration(&self, response: AttestationResponse) -> Result<RegistrationComplete>;
    async fn start_authentication(&self, request: AuthenticationRequest) -> Result<RequestChallengeResponse>;
    async fn finish_authentication(&self, response: AssertionResponse) -> Result<AuthenticationComplete>;
}
```

### 2.2 Testing Strategy for WebAuthn

**Unit Tests (95%+ coverage target):**
- Challenge generation and validation
- Attestation verification logic
- User verification policy enforcement
- Error handling for all failure modes

**Integration Tests:**
- End-to-end registration flow
- End-to-end authentication flow
- Database integration with real PostgreSQL
- WebAuthn library integration

**Security Tests:**
- Replay attack prevention
- Challenge uniqueness validation
- Cryptographic verification testing
- Input validation and sanitization

**Compliance Tests:**
- WebAuthn Level 2 specification compliance
- FIDO Alliance compliance
- Attestation format support validation

## 3. API Layer Design (Test-First)

### 3.1 REST Endpoints with Comprehensive Testing

```rust
// Controller design with dependency injection
pub struct RegistrationController {
    webauthn_service: Arc<dyn WebAuthnServiceTrait>,
    rate_limiter: Arc<dyn RateLimiter>,
    validator: Arc<dyn RequestValidator>,
}

// Each endpoint will have corresponding test modules:
// - tests/unit/controllers/registration_test.rs
// - tests/integration/registration_flow_test.rs
// - tests/security/registration_security_test.rs
```

### 3.2 Error Handling Architecture

```rust
// Comprehensive error types for testing
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Security violation: {0}")]
    SecurityViolation(String),
}

// Each error variant will have dedicated tests
```

## 4. Storage Layer Architecture

### 4.1 Repository Pattern for Testability

```rust
// Abstract repositories for easy mocking
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<User>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>>;
    async fn update_user(&self, user: &User) -> Result<User>;
    async fn delete_user(&self, user_id: Uuid) -> Result<()>;
}

// Mock implementation for testing
pub struct MockUserRepository {
    users: Arc<Mutex<HashMap<Uuid, User>>>,
}

// Production implementation with Diesel
pub struct DieselUserRepository {
    pool: Arc<DbPool>,
}
```

### 4.2 Database Schema with Security Constraints

```sql
-- Users table with security constraints
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL, -- 16-byte WebAuthn user handle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    login_count BIGINT DEFAULT 0,
    
    -- Security fields
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT valid_username CHECK (username ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_display_name CHECK (LENGTH(display_name) >= 1 AND LENGTH(display_name) <= 255)
);

-- Credentials table with WebAuthn data
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    user_verified BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    transports JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    -- Security constraints
    CONSTRAINT valid_credential_id CHECK (LENGTH(credential_id) >= 16),
    CONSTRAINT valid_sign_count CHECK (sign_count >= 0)
);

-- Challenges table for replay protection
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id VARCHAR(255) UNIQUE NOT NULL,
    challenge_data BYTEA NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Security constraints
    CONSTRAINT valid_challenge_type CHECK (challenge_type IN ('registration', 'authentication')),
    CONSTRAINT valid_expiry CHECK (expires_at > created_at)
);
```

## 5. Security Patterns (Testable)

### 5.1 Security Service Architecture

```rust
pub struct SecurityService {
    challenge_store: Arc<dyn ChallengeStore>,
    rate_limiter: Arc<dyn RateLimiter>,
    audit_logger: Arc<dyn AuditLogger>,
    config: SecurityConfig,
}

#[async_trait]
pub trait SecurityServiceTrait {
    async fn validate_challenge(&self, challenge: &str, user_id: Uuid) -> Result<()>;
    async fn check_rate_limit(&self, client_ip: &str) -> Result<()>;
    async fn log_security_event(&self, event: SecurityEvent) -> Result<()>;
    async fn detect_anomalies(&self, user_id: Uuid) -> Result<Vec<SecurityAlert>>;
}
```

### 5.2 Security Testing Strategy

**Input Validation Tests:**
- SQL injection prevention
- XSS prevention
- Path traversal prevention
- Command injection prevention

**Authentication Security Tests:**
- Brute force attack prevention
- Timing attack resistance
- Replay attack prevention
- Session hijacking prevention

**Cryptographic Security Tests:**
- Challenge entropy validation
- Random number generation quality
- Cryptographic algorithm validation
- Key storage security

## 6. Testing Architecture (Comprehensive)

### 6.1 Test Structure

```
tests/
├── lib.rs                    # Test common utilities
├── common/                   # Shared test utilities
│   ├── mod.rs
│   ├── fixtures.rs          # Test data fixtures
│   ├── mocks.rs             # Mock implementations
│   └── test_utils.rs        # Test helper functions
├── unit/                     # Unit tests (fast, isolated)
│   ├── services/
│   │   ├── fido_test.rs
│   │   ├── user_test.rs
│   │   ├── credential_test.rs
│   │   └── security_test.rs
│   ├── controllers/
│   │   ├── registration_test.rs
│   │   ├── authentication_test.rs
│   │   └── credential_test.rs
│   ├── db/
│   │   ├── repositories_test.rs
│   │   └── models_test.rs
│   └── utils/
│       ├── crypto_test.rs
│       └── validation_test.rs
├── integration/              # Integration tests (slower, realistic)
│   ├── api_test.rs          # Full API integration tests
│   ├── database_test.rs     # Database integration tests
│   ├── webauthn_test.rs     # WebAuthn library integration
│   └── end_to_end_test.rs   # Complete flow tests
├── security/                 # Security tests (specialized)
│   ├── authentication_test.rs
│   ├── authorization_test.rs
│   ├── input_validation_test.rs
│   ├── replay_protection_test.rs
│   ├── timing_attack_test.rs
│   └── compliance_test.rs
├── performance/              # Performance tests
│   ├── load_test.rs         # Load testing
│   ├── benchmark_test.rs    # Performance benchmarks
│   └── memory_test.rs       # Memory usage tests
└── compliance/               # Compliance tests
    ├── webauthn_spec_test.rs
    ├── fido_compliance_test.rs
    └── security_compliance_test.rs
```

### 6.2 Test Data Management

```rust
// Test fixtures for consistent test data
pub struct TestFixtures {
    users: Vec<User>,
    credentials: Vec<Credential>,
    challenges: Vec<Challenge>,
}

// Property-based testing with proptest
proptest! {
    #[test]
    fn test_challenge_generation_properties(bytes in any::<[u8; 32]>()) {
        // Test challenge generation properties
    }
}
```

## 7. Dependency Injection Architecture

### 7.1 Service Container

```rust
pub struct ServiceContainer {
    webauthn_service: Arc<dyn WebAuthnServiceTrait>,
    user_service: Arc<dyn UserServiceTrait>,
    credential_service: Arc<dyn CredentialServiceTrait>,
    security_service: Arc<dyn SecurityServiceTrait>,
}

// Easy creation of test containers
impl ServiceContainer {
    pub fn for_production(config: Config) -> Self { /* ... */ }
    pub fn for_testing() -> Self { /* ... */ }
    pub fn for_integration() -> Self { /* ... */ }
}
```

### 7.2 Mock Strategy

```rust
// Comprehensive mocking with mockall
#[cfg(test)]
mock! {
    pub WebAuthnService {}

    #[async_trait]
    impl WebAuthnServiceTrait for WebAuthnService {
        async fn start_registration(&self, request: RegistrationRequest) -> Result<CreationChallengeResponse>;
        async fn finish_registration(&self, response: AttestationResponse) -> Result<RegistrationComplete>;
        async fn start_authentication(&self, request: AuthenticationRequest) -> Result<RequestChallengeResponse>;
        async fn finish_authentication(&self, response: AssertionResponse) -> Result<AuthenticationComplete>;
    }
}
```

## 8. Performance Testing Strategy

### 8.1 Load Testing

```rust
// Criterion benchmarks for performance validation
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_challenge_generation(c: &mut Criterion) {
    c.bench_function("challenge_generation", |b| {
        b.iter(|| {
            black_box(generate_challenge())
        })
    });
}

// Load testing with concurrent operations
#[tokio::test]
async fn test_concurrent_registrations() {
    let service = create_test_service();
    let handles: Vec<_> = (0..100).map(|_| {
        let service = service.clone();
        tokio::spawn(async move {
            service.start_registration(create_test_request()).await
        })
    }).collect();
    
    let results = futures::future::join_all(handles).await;
    assert_all_success(results);
}
```

## 9. Implementation Priority

### Phase 1: Core WebAuthn Integration (Week 1-2)
1. Enhance FidoService with full webauthn-rs integration
2. Implement repository pattern with mock support
3. Create comprehensive unit tests for core functionality
4. Add basic security validation

### Phase 2: API Layer & Controllers (Week 3)
1. Implement REST endpoints with proper error handling
2. Add request validation and sanitization
3. Create integration tests for API endpoints
4. Add rate limiting and security middleware

### Phase 3: Security & Compliance (Week 4)
1. Implement comprehensive security testing
2. Add compliance validation tests
3. Implement audit logging
4. Add performance benchmarks

### Phase 4: Advanced Features (Week 5-6)
1. Add credential management endpoints
2. Implement advanced security features
3. Add monitoring and observability
4. Complete documentation and deployment guides

This architecture ensures comprehensive testability, security, and maintainability while following Rust best practices and TDD principles.