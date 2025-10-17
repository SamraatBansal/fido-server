# Test-Driven Architecture Plan for FIDO2/WebAuthn Relying Party Server

## Executive Summary

This document provides a comprehensive test-driven architecture plan for implementing a FIDO2/WebAuthn Relying Party Server in Rust. The architecture prioritizes testability, security validation, and maintainability while leveraging the webauthn-rs library effectively. Every component is designed with testing in mind, following Test-Driven Development (TDD) principles.

## 1. Architecture Overview

### 1.1 Design Principles

#### Testability First
- **Dependency Injection**: All external dependencies injected through traits
- **Pure Functions**: Business logic implemented as pure functions where possible
- **Deterministic Behavior**: All functions have predictable outputs for given inputs
- **Mockable Interfaces**: All external services have trait-based interfaces for mocking

#### Security by Design
- **Defense in Depth**: Multiple layers of security validation
- **Fail Secure**: Default to secure behavior on errors
- **Zero Trust**: Validate all inputs, even from trusted sources
- **Audit Trail**: Comprehensive logging for security events

#### Maintainability
- **Single Responsibility**: Each module has one clear purpose
- **Interface Segregation**: Small, focused interfaces
- **Dependency Inversion**: Depend on abstractions, not concretions
- **Explicit Dependencies**: All dependencies clearly declared

### 1.2 Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    API Layer (Controllers)                  │
├─────────────────────────────────────────────────────────────┤
│                  Service Layer (Business Logic)             │
├─────────────────────────────────────────────────────────────┤
│                Repository Layer (Data Access)               │
├─────────────────────────────────────────────────────────────┤
│                 Infrastructure Layer (External)             │
└─────────────────────────────────────────────────────────────┘
```

## 2. Core Architecture Components

### 2.1 WebAuthn Service Architecture

#### Core WebAuthn Service
```rust
// src/services/webauthn.rs
pub trait WebAuthnService: Send + Sync {
    async fn generate_attestation_options(
        &self,
        request: AttestationOptionsRequest,
    ) -> Result<AttestationOptionsResponse, WebAuthnError>;
    
    async fn verify_attestation(
        &self,
        request: AttestationVerificationRequest,
    ) -> Result<AttestationVerificationResponse, WebAuthnError>;
    
    async fn generate_assertion_options(
        &self,
        request: AssertionOptionsRequest,
    ) -> Result<AssertionOptionsResponse, WebAuthnError>;
    
    async fn verify_assertion(
        &self,
        request: AssertionVerificationRequest,
    ) -> Result<AssertionVerificationResponse, WebAuthnError>;
}
```

#### Challenge Management Service
```rust
// src/services/challenge.rs
pub trait ChallengeService: Send + Sync {
    async fn create_challenge(
        &self,
        user_id: &str,
        challenge_type: ChallengeType,
    ) -> Result<Challenge, ChallengeError>;
    
    async fn verify_and_consume_challenge(
        &self,
        challenge_id: &str,
        user_id: &str,
        challenge_type: ChallengeType,
    ) -> Result<(), ChallengeError>;
    
    async fn cleanup_expired_challenges(&self) -> Result<usize, ChallengeError>;
}
```

#### Credential Management Service
```rust
// src/services/credential.rs
pub trait CredentialService: Send + Sync {
    async fn register_credential(
        &self,
        credential: NewCredential,
    ) -> Result<CredentialId, CredentialError>;
    
    async fn get_user_credentials(
        &self,
        user_id: &str,
    ) -> Result<Vec<Credential>, CredentialError>;
    
    async fn update_credential_usage(
        &self,
        credential_id: &str,
        counter: u32,
    ) -> Result<(), CredentialError>;
    
    async fn revoke_credential(
        &self,
        credential_id: &str,
    ) -> Result<(), CredentialError>;
}
```

### 2.2 Repository Pattern Implementation

#### Base Repository Trait
```rust
// src/db/repositories.rs
pub trait Repository<T, ID>: Send + Sync {
    async fn create(&self, entity: T) -> Result<ID, RepositoryError>;
    async fn find_by_id(&self, id: ID) -> Result<Option<T>, RepositoryError>;
    async fn update(&self, entity: T) -> Result<(), RepositoryError>;
    async fn delete(&self, id: ID) -> Result<(), RepositoryError>;
}

pub trait ChallengeRepository: Repository<Challenge, String> {
    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        challenge_type: ChallengeType,
    ) -> Result<Vec<Challenge>, RepositoryError>;
    
    async fn delete_expired(&self, before: DateTime<Utc>) -> Result<usize, RepositoryError>;
}

pub trait CredentialRepository: Repository<Credential, CredentialId> {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<Credential>, RepositoryError>;
    async fn find_by_credential_id(&self, credential_id: &str) -> Result<Option<Credential>, RepositoryError>;
}
```

### 2.3 Configuration Management

#### Testable Configuration
```rust
// src/config/app.rs
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub webauthn: WebAuthnConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub server: ServerConfig,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load from environment with validation
    }
    
    pub fn for_testing() -> Self {
        // Default test configuration
    }
}

#[cfg(test)]
impl Default for AppConfig {
    fn default() -> Self {
        Self::for_testing()
    }
}
```

## 3. Testing Strategy

### 3.1 Test Pyramid Architecture

```
                    ┌─────────────────┐
                    │   E2E Tests     │ (5%)
                    │   (Integration) │
                    └─────────────────┘
                ┌─────────────────────────┐
                │   Integration Tests     │ (25%)
                │   (API + Database)      │
                └─────────────────────────┘
        ┌─────────────────────────────────────────┐
        │           Unit Tests                     │ (70%)
        │   (Services, Repositories, Utils)        │
        └─────────────────────────────────────────┘
```

### 3.2 Unit Testing Strategy

#### Service Layer Tests
```rust
// tests/unit/services/webauthn_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    
    #[tokio::test]
    async fn test_generate_attestation_options_success() {
        // Arrange
        let mut challenge_service = MockChallengeService::new();
        challenge_service
            .expect_create_challenge()
            .with(eq("user123"), eq(ChallengeType::Attestation))
            .returning(|_, _| Ok(create_test_challenge()));
        
        let mut credential_service = MockCredentialService::new();
        credential_service
            .expect_get_user_credentials()
            .with(eq("user123"))
            .returning(|_| Ok(vec![]));
        
        let webauthn_service = WebAuthnServiceImpl::new(
            challenge_service,
            credential_service,
            create_test_webauthn_config(),
        );
        
        let request = AttestationOptionsRequest {
            username: "user123".to_string(),
            display_name: "Test User".to_string(),
            user_verification: UserVerificationPolicy::Preferred,
            ..Default::default()
        };
        
        // Act
        let result = webauthn_service.generate_attestation_options(request).await;
        
        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.user.name, "user123");
        assert_eq!(response.user.display_name, "Test User");
        assert!(!response.challenge.is_empty());
        assert!(response.timeout > 0);
    }
    
    #[tokio::test]
    async fn test_generate_attestation_options_challenge_error() {
        // Test error propagation from challenge service
    }
    
    #[tokio::test]
    async fn test_verify_attestation_success() {
        // Test successful attestation verification
    }
    
    #[tokio::test]
    async fn test_verify_attestation_invalid_challenge() {
        // Test challenge validation failure
    }
    
    #[tokio::test]
    async fn test_verify_attestation_duplicate_credential() {
        // Test duplicate credential detection
    }
}
```

#### Repository Layer Tests
```rust
// tests/unit/db/repositories_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    
    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }
    
    #[tokio::test]
    async fn test_challenge_repository_create_and_find() {
        // Arrange
        let pool = setup_test_db().await;
        let repo = ChallengeRepositoryImpl::new(pool.clone());
        let challenge = create_test_challenge();
        
        // Act
        let id = repo.create(challenge.clone()).await.unwrap();
        let found = repo.find_by_id(id.clone()).await.unwrap();
        
        // Assert
        assert!(found.is_some());
        let found_challenge = found.unwrap();
        assert_eq!(found_challenge.user_id, challenge.user_id);
        assert_eq!(found_challenge.challenge_type, challenge.challenge_type);
    }
    
    #[tokio::test]
    async fn test_challenge_repository_find_by_user_and_type() {
        // Test user-specific challenge retrieval
    }
    
    #[tokio::test]
    async fn test_challenge_repository_delete_expired() {
        // Test expired challenge cleanup
    }
}
```

### 3.3 Integration Testing Strategy

#### API Integration Tests
```rust
// tests/integration/api/attestation_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    
    #[tokio::test]
    async fn test_attestation_options_endpoint_success() {
        // Arrange
        let app = test::init_service(
            App::new()
                .configure(configure_routes)
                .app_data(create_test_app_state())
        ).await;
        
        let req = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(AttestationOptionsRequest {
                username: "test@example.com".to_string(),
                display_name: "Test User".to_string(),
                ..Default::default()
            })
            .to_request();
        
        // Act
        let resp = test::call_service(&app, req).await;
        
        // Assert
        assert!(resp.status().is_success());
        
        let response: AttestionOptionsResponse = test::read_body_json(resp).await;
        assert_eq!(response.user.name, "test@example.com");
        assert!(!response.challenge.is_empty());
        assert!(response.pub_key_cred_params.len() > 0);
    }
    
    #[tokio::test]
    async fn test_attestation_result_endpoint_success() {
        // Test complete attestation flow
    }
    
    #[tokio::test]
    async fn test_attestation_result_invalid_challenge() {
        // Test challenge validation in API layer
    }
}
```

#### WebAuthn Integration Tests
```rust
// tests/integration/webauthn/flows_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
    
    #[tokio::test]
    async fn test_complete_registration_flow() {
        // Arrange
        let app_state = create_test_app_state();
        let mut authenticator = SoftPasskey::new();
        
        // Step 1: Get attestation options
        let options_request = AttestationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            ..Default::default()
        };
        
        let options_response = app_state
            .webauthn_service
            .generate_attestation_options(options_request)
            .await
            .unwrap();
        
        // Step 2: Create credential with authenticator
        let credential_creation = authenticator
            .do_registration(options_response.into())
            .await
            .unwrap();
        
        // Step 3: Verify attestation
        let verification_request = AttestationVerificationRequest::from(credential_creation);
        let verification_response = app_state
            .webauthn_service
            .verify_attestation(verification_request)
            .await
            .unwrap();
        
        // Assert
        assert!(verification_response.success);
        assert!(!verification_response.credential_id.is_empty());
    }
    
    #[tokio::test]
    async fn test_complete_authentication_flow() {
        // Test complete authentication flow
    }
}
```

### 3.4 Security Testing Strategy

#### Security Test Suite
```rust
// tests/security/security_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_replay_attack_prevention() {
        // Arrange
        let app_state = create_test_app_state();
        let challenge = create_test_challenge();
        
        // Use challenge once
        let result1 = app_state
            .challenge_service
            .verify_and_consume_challenge(&challenge.id, &challenge.user_id, challenge.challenge_type)
            .await;
        assert!(result1.is_ok());
        
        // Try to use same challenge again
        let result2 = app_state
            .challenge_service
            .verify_and_consume_challenge(&challenge.id, &challenge.user_id, challenge.challenge_type)
            .await;
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), ChallengeError::ChallengeAlreadyUsed));
    }
    
    #[tokio::test]
    async fn test_challenge_expiration() {
        // Test expired challenge rejection
    }
    
    #[tokio::test]
    async fn test_origin_validation() {
        // Test malicious origin rejection
    }
    
    #[tokio::test]
    async fn test_rp_id_validation() {
        // Test RP ID validation
    }
    
    #[tokio::test]
    async fn test_input_validation() {
        // Test input sanitization and validation
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        // Test rate limiting enforcement
    }
}
```

## 4. Error Handling Architecture

### 4.1 Error Type Hierarchy
```rust
// src/error/types.rs
#[derive(Debug, thiserror::Error)]
pub enum WebAuthnError {
    #[error("Challenge error: {0}")]
    Challenge(#[from] ChallengeError),
    
    #[error("Credential error: {0}")]
    Credential(#[from] CredentialError),
    
    #[error("Repository error: {0}")]
    Repository(#[from] RepositoryError),
    
    #[error("WebAuthn protocol error: {0}")]
    Protocol(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("Challenge not found")]
    NotFound,
    
    #[error("Challenge already used")]
    AlreadyUsed,
    
    #[error("Challenge expired")]
    Expired,
    
    #[error("Invalid challenge format")]
    InvalidFormat,
    
    #[error("Storage error: {0}")]
    Storage(#[from] RepositoryError),
}
```

### 4.2 Error Response Testing
```rust
// tests/unit/error/handlers_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_response_serialization() {
        let error = WebAuthnError::Challenge(ChallengeError::Expired);
        let response = ErrorResponse::from(error);
        
        let json = serde_json::to_string(&response).unwrap();
        let parsed: ErrorResponse = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.error_code, "CHALLENGE_EXPIRED");
        assert!(!parsed.message.is_empty());
        assert!(parsed.timestamp > 0);
    }
}
```

## 5. Performance Testing Strategy

### 5.1 Load Testing Architecture
```rust
// tests/performance/load_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    
    #[tokio::test]
    async fn test_concurrent_attestation_options() {
        let app_state = create_test_app_state();
        let concurrent_requests = 100;
        
        let start = Instant::now();
        let mut handles = vec![];
        
        for i in 0..concurrent_requests {
            let state = app_state.clone();
            let handle = tokio::spawn(async move {
                let request = AttestationOptionsRequest {
                    username: format!("user{}", i),
                    display_name: format!("User {}", i),
                    ..Default::default()
                };
                
                state.webauthn_service.generate_attestation_options(request).await
            });
            handles.push(handle);
        }
        
        let results = futures::future::join_all(handles).await;
        let duration = start.elapsed();
        
        // Assert all requests succeeded
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }
        
        // Assert performance requirements
        assert!(duration < Duration::from_secs(5));
        let avg_response_time = duration / concurrent_requests;
        assert!(avg_response_time < Duration::from_millis(100));
    }
}
```

## 6. Test Data Management

### 6.1 Test Fixtures
```rust
// tests/common/fixtures.rs
pub struct TestFixtures;

impl TestFixtures {
    pub fn create_test_user() -> User {
        User {
            id: "test-user-123".to_string(),
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    pub fn create_test_challenge() -> Challenge {
        Challenge {
            id: "challenge-123".to_string(),
            user_id: "test-user-123".to_string(),
            challenge_data: base64::encode("random-challenge-data"),
            challenge_type: ChallengeType::Attestation,
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
            used: false,
        }
    }
    
    pub fn create_test_credential() -> Credential {
        Credential {
            id: CredentialId::new(),
            user_id: "test-user-123".to_string(),
            credential_data: "credential-data".to_string(),
            public_key: "public-key".to_string(),
            sign_count: 0,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            attestation_type: AttestationType::None,
            aaguid: None,
        }
    }
}
```

### 6.2 Test Database Management
```rust
// tests/common/database.rs
pub struct TestDatabase {
    pool: SqlitePool,
}

impl TestDatabase {
    pub async fn new() -> Self {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        Self { pool }
    }
    
    pub async fn reset(&self) {
        // Clean all tables
        sqlx::query("DELETE FROM challenges").execute(&self.pool).await.unwrap();
        sqlx::query("DELETE FROM credentials").execute(&self.pool).await.unwrap();
        sqlx::query("DELETE FROM users").execute(&self.pool).await.unwrap();
    }
    
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
impl Drop for TestDatabase {
    fn drop(&mut self) {
        self.pool.close();
    }
}
```

## 7. Continuous Integration Testing

### 7.1 CI Test Pipeline
```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
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
    
    - name: Run formatting checks
      run: cargo fmt --all -- --check
    
    - name: Run clippy
      run: cargo clippy --all-targets --all-features -- -D warnings
    
    - name: Run unit tests
      run: cargo test --lib --bins
    
    - name: Run integration tests
      run: cargo test --test '*'
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/postgres
    
    - name: Run security tests
      run: cargo test security
    
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./cobertura.xml
```

## 8. Implementation Roadmap with TDD

### 8.1 Phase 1: Foundation (Week 1-2)
1. **Setup Project Structure**
   - Create directory structure
   - Configure Cargo.toml with test dependencies
   - Setup CI/CD pipeline

2. **Implement Core Traits**
   - Define service interfaces
   - Create repository traits
   - Setup error types

3. **Write First Tests**
   - Test configuration loading
   - Test error handling
   - Test basic utilities

### 8.2 Phase 2: Challenge Management (Week 2-3)
1. **Challenge Service Tests**
   - Write tests for challenge generation
   - Write tests for challenge validation
   - Write tests for expiration logic

2. **Challenge Repository Tests**
   - Write tests for storage operations
   - Write tests for cleanup operations

3. **Implementation**
   - Implement challenge service
   - Implement challenge repository
   - Ensure all tests pass

### 8.3 Phase 3: WebAuthn Core (Week 3-5)
1. **WebAuthn Service Tests**
   - Write tests for attestation options
   - Write tests for attestation verification
   - Write tests for assertion options
   - Write tests for assertion verification

2. **Credential Service Tests**
   - Write tests for credential registration
   - Write tests for credential retrieval
   - Write tests for credential updates

3. **Implementation**
   - Implement WebAuthn service using webauthn-rs
   - Implement credential service
   - Integrate with challenge management

### 8.4 Phase 4: API Layer (Week 5-6)
1. **Controller Tests**
   - Write tests for all endpoints
   - Write tests for error handling
   - Write tests for input validation

2. **Integration Tests**
   - Write end-to-end API tests
   - Write WebAuthn flow tests
   - Write security tests

3. **Implementation**
   - Implement controllers
   - Setup routing
   - Add middleware

### 8.5 Phase 5: Security & Performance (Week 6-7)
1. **Security Tests**
   - Write replay attack tests
   - Write input validation tests
   - Write rate limiting tests

2. **Performance Tests**
   - Write load tests
   - Write concurrency tests
   - Optimize based on results

3. **Security Hardening**
   - Implement security headers
   - Add rate limiting
   - Implement audit logging

### 8.6 Phase 6: Compliance & Documentation (Week 7-8)
1. **Compliance Tests**
   - Write FIDO2 conformance tests
   - Verify all security requirements
   - Run compliance test suite

2. **Documentation**
   - Update API documentation
   - Create deployment guides
   - Write security documentation

3. **Final Validation**
   - Run complete test suite
   - Performance validation
   - Security audit

## 9. Success Metrics

### 9.1 Testing Metrics
- **Unit Test Coverage**: ≥95%
- **Integration Test Coverage**: 100% of API endpoints
- **Security Test Coverage**: 100% of security requirements
- **Performance Test Coverage**: All critical paths under load

### 9.2 Quality Metrics
- **Code Coverage**: ≥90% line coverage
- **Mutation Score**: ≥80%
- **Static Analysis**: Zero clippy warnings
- **Documentation**: 100% public API documented

### 9.3 Performance Metrics
- **Response Time**: <100ms for 95th percentile
- **Throughput**: ≥1000 requests/second
- **Concurrent Users**: ≥100 simultaneous users
- **Memory Usage**: <512MB under normal load

## 10. Conclusion

This test-driven architecture plan provides a comprehensive foundation for building a secure, reliable, and maintainable FIDO2/WebAuthn Relying Party Server. By prioritizing testability at every layer and following TDD principles, the implementation will have:

- **High Quality**: Comprehensive test coverage ensures robustness
- **Security**: Automated security validation prevents vulnerabilities
- **Maintainability**: Clean architecture with clear separation of concerns
- **Performance**: Load testing ensures scalability requirements are met
- **Compliance**: Automated verification of FIDO2 requirements

The architecture leverages Rust's type system and the webauthn-rs library effectively while ensuring every component can be thoroughly tested in isolation and integration.