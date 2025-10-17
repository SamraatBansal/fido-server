# FIDO2/WebAuthn Server Testing Strategy

## Overview

This document outlines the comprehensive testing strategy for the FIDO2/WebAuthn Relying Party Server, ensuring security, compliance, and reliability through test-driven development.

## 1. Testing Pyramid

### 1.1 Unit Tests (70%)
- **Purpose**: Test individual functions and methods in isolation
- **Coverage Target**: 95%+ line coverage
- **Tools**: Rust's built-in test framework, mockall for mocking
- **Execution**: Fast (<1s per test), run on every commit

### 1.2 Integration Tests (20%)
- **Purpose**: Test component interactions and API endpoints
- **Coverage Target**: 100% API endpoint coverage
- **Tools**: actix-test, testcontainers for database testing
- **Execution**: Medium speed (<10s per test), run on PR

### 1.3 End-to-End Tests (10%)
- **Purpose**: Test complete user flows and system behavior
- **Coverage Target**: All critical user journeys
- **Tools**: Browser automation, real authenticator simulation
- **Execution**: Slow (<60s per test), run on main branch

## 2. Unit Testing Strategy

### 2.1 Service Layer Tests

#### WebAuthn Service Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use webauthn_rs::prelude::*;

    #[tokio::test]
    async fn test_generate_attestation_challenge_success() {
        // Test successful challenge generation
        let webauthn = create_test_webauthn();
        let user = create_test_user();
        
        let result = webauthn.generate_attestation_challenge(&user).await;
        
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.user.id, user.id);
    }

    #[tokio::test]
    async fn test_generate_attestation_challenge_invalid_user() {
        // Test challenge generation with invalid user
        let webauthn = create_test_webauthn();
        let invalid_user = create_invalid_user();
        
        let result = webauthn.generate_attestation_challenge(&invalid_user).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidUser));
    }

    #[tokio::test]
    async fn test_verify_attestation_success() {
        // Test successful attestation verification
        let webauthn = create_test_webauthn();
        let attestation = create_valid_attestation();
        
        let result = webauthn.verify_attestation(&attestation).await;
        
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert!(!credential.credential_id.is_empty());
    }

    #[tokio::test]
    async fn test_verify_attestation_invalid_signature() {
        // Test attestation verification with invalid signature
        let webauthn = create_test_webauthn();
        let attestation = create_attestation_with_invalid_signature();
        
        let result = webauthn.verify_attestation(&attestation).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidSignature));
    }
}
```

#### Credential Service Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    mock! {
        CredentialRepository {}

        #[async_trait]
        impl CredentialRepositoryTrait for CredentialRepository {
            async fn save_credential(&self, credential: &Credential) -> Result<(), RepositoryError>;
            async fn find_by_id(&self, id: &str) -> Result<Option<Credential>, RepositoryError>;
            async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<Credential>, RepositoryError>;
            async fn update_sign_count(&self, id: &str, count: u64) -> Result<(), RepositoryError>;
            async fn delete_credential(&self, id: &str) -> Result<(), RepositoryError>;
        }
    }

    #[tokio::test]
    async fn test_save_credential_success() {
        let mut mock_repo = MockCredentialRepository::new();
        let credential = create_test_credential();
        
        mock_repo
            .expect_save_credential()
            .with(eq(credential.clone()))
            .times(1)
            .returning(|_| Ok(()));

        let service = CredentialService::new(Box::new(mock_repo));
        let result = service.save_credential(&credential).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_save_credential_duplicate_id() {
        let mut mock_repo = MockCredentialRepository::new();
        let credential = create_test_credential();
        
        mock_repo
            .expect_save_credential()
            .with(eq(credential.clone()))
            .times(1)
            .returning(|_| Err(RepositoryError::DuplicateKey));

        let service = CredentialService::new(Box::new(mock_repo));
        let result = service.save_credential(&credential).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CredentialError::DuplicateCredential));
    }
}
```

### 2.2 Controller Tests

#### Attestation Controller Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use serde_json::json;

    #[actix_web::test]
    async fn test_attestation_options_success() {
        let webauthn_service = create_mock_webauthn_service();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .service(attestation_options)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(json!({
                "username": "testuser",
                "displayName": "Test User",
                "attestation": "none",
                "authenticatorSelection": {
                    "userVerification": "preferred"
                }
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        
        assert_eq!(resp.status(), 200);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["challenge"].is_string());
        assert_eq!(body["user"]["name"], "testuser");
    }

    #[actix_web::test]
    async fn test_attestation_options_invalid_request() {
        let webauthn_service = create_mock_webauthn_service();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .service(attestation_options)
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(json!({
                "username": "",  // Invalid empty username
                "displayName": "Test User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        
        assert_eq!(resp.status(), 400);
    }
}
```

### 2.3 Utility Tests

#### Validation Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        let valid_usernames = vec![
            "user123",
            "test.user",
            "user_name",
            "user@domain",
            "123user"
        ];

        for username in valid_usernames {
            assert!(validate_username(username).is_ok());
        }
    }

    #[test]
    fn test_validate_username_invalid() {
        let invalid_usernames = vec![
            "",           // Empty
            "ab",         // Too short
            "a".repeat(65).as_str(),  // Too long
            "user name",  // Space
            "user#name",  // Invalid character
            "user/name",  // Invalid character
        ];

        for username in invalid_usernames {
            assert!(validate_username(username).is_err());
        }
    }

    #[test]
    fn test_validate_credential_id_valid() {
        let valid_ids = vec![
            "AQIDBAUGBwgJCgsMDQ4PEA",
            "dGVzdC1jcmVkZW50aWFsLWlk",
            "1234567890abcdef1234567890abcdef"
        ];

        for id in valid_ids {
            assert!(validate_credential_id(id).is_ok());
        }
    }

    #[test]
    fn test_validate_credential_id_invalid() {
        let invalid_ids = vec![
            "",                    // Empty
            "invalid-base64!",     // Invalid characters
            "a".repeat(1025).as_str(),  // Too long
        ];

        for id in invalid_ids {
            assert!(validate_credential_id(id).is_err());
        }
    }
}
```

## 3. Integration Testing Strategy

### 3.1 API Endpoint Integration Tests

#### Complete Registration Flow Test
```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use actix_web::{test, web, App};
    use testcontainers::{clients::Cli, images::postgres::Postgres, Container};
    use diesel::prelude::*;

    struct TestApp {
        app: actix_web::test::TestServer,
        db_container: Container<'static, Postgres>,
        db_pool: DbPool,
    }

    impl TestApp {
        async fn new() -> Self {
            let docker = Cli::default();
            let postgres_container = docker.run(Postgres::default());
            let connection_string = format!(
                "postgres://postgres:postgres@localhost:{}/testdb",
                postgres_container.get_host_port_ipv4(5432)
            );

            // Run migrations
            run_migrations(&connection_string).await;

            let db_pool = create_db_pool(&connection_string).await;
            let webauthn_service = WebAuthnService::new(db_pool.clone());

            let app = test::init_service(
                App::new()
                    .app_data(web::Data::new(webauthn_service))
                    .app_data(web::Data::new(db_pool))
                    .configure(configure_routes)
            ).await;

            Self {
                app,
                db_container: postgres_container,
                db_pool,
            }
        }
    }

    #[actix_web::test]
    async fn test_complete_registration_flow() {
        let test_app = TestApp::new().await;

        // Step 1: Get attestation options
        let options_request = serde_json::json!({
            "username": "testuser",
            "displayName": "Test User",
            "attestation": "none",
            "authenticatorSelection": {
                "userVerification": "preferred"
            }
        });

        let options_resp = test_app
            .app
            .post("/attestation/options")
            .send_json(&options_request)
            .await
            .unwrap();

        assert_eq!(options_resp.status(), 200);
        let options_body: serde_json::Value = options_resp.json().await.unwrap();
        let challenge = options_body["challenge"].as_str().unwrap();

        // Step 2: Create mock attestation response
        let attestation_response = create_mock_attestation_response(challenge);

        // Step 3: Submit attestation result
        let result_resp = test_app
            .app
            .post("/attestation/result")
            .send_json(&attestation_response)
            .await
            .unwrap();

        assert_eq!(result_resp.status(), 200);
        let result_body: serde_json::Value = result_resp.json().await.unwrap();
        assert_eq!(result_body["status"], "ok");

        // Step 4: Verify credential was stored
        let credential_id = result_body["credentialId"].as_str().unwrap();
        let stored_credential = find_credential_by_id(&test_app.db_pool, credential_id).await;
        assert!(stored_credential.is_some());
    }

    #[actix_web::test]
    async fn test_complete_authentication_flow() {
        let test_app = TestApp::new().await;

        // First, register a credential
        let credential_id = register_test_credential(&test_app).await;

        // Step 1: Get assertion options
        let options_request = serde_json::json!({
            "username": "testuser",
            "userVerification": "preferred"
        });

        let options_resp = test_app
            .app
            .post("/assertion/options")
            .send_json(&options_request)
            .await
            .unwrap();

        assert_eq!(options_resp.status(), 200);
        let options_body: serde_json::Value = options_resp.json().await.unwrap();
        let challenge = options_body["challenge"].as_str().unwrap();

        // Step 2: Create mock assertion response
        let assertion_response = create_mock_assertion_response(challenge, &credential_id);

        // Step 3: Submit assertion result
        let result_resp = test_app
            .app
            .post("/assertion/result")
            .send_json(&assertion_response)
            .await
            .unwrap();

        assert_eq!(result_resp.status(), 200);
        let result_body: serde_json::Value = result_resp.json().await.unwrap();
        assert_eq!(result_body["status"], "ok");
    }
}
```

### 3.2 Database Integration Tests

#### Repository Tests
```rust
#[cfg(test)]
mod repository_tests {
    use super::*;
    use testcontainers::{clients::Cli, images::postgres::Postgres};

    #[tokio::test]
    async fn test_credential_repository_crud() {
        let docker = Cli::default();
        let postgres_container = docker.run(Postgres::default());
        let connection_string = format!(
            "postgres://postgres:postgres@localhost:{}/testdb",
            postgres_container.get_host_port_ipv4(5432)
        );

        run_migrations(&connection_string).await;
        let pool = create_db_pool(&connection_string).await;
        let repo = CredentialRepository::new(pool);

        // Create
        let credential = create_test_credential();
        let create_result = repo.save_credential(&credential).await;
        assert!(create_result.is_ok());

        // Read
        let found_credential = repo.find_by_id(&credential.credential_id).await.unwrap();
        assert!(found_credential.is_some());
        assert_eq!(found_credential.unwrap().credential_id, credential.credential_id);

        // Update
        let update_result = repo.update_sign_count(&credential.credential_id, 1).await;
        assert!(update_result.is_ok());

        let updated_credential = repo.find_by_id(&credential.credential_id).await.unwrap().unwrap();
        assert_eq!(updated_credential.sign_count, 1);

        // Delete
        let delete_result = repo.delete_credential(&credential.credential_id).await;
        assert!(delete_result.is_ok());

        let deleted_credential = repo.find_by_id(&credential.credential_id).await.unwrap();
        assert!(deleted_credential.is_none());
    }
}
```

## 4. Security Testing Strategy

### 4.1 FIDO2 Compliance Tests

#### Attestation Compliance Tests
```rust
#[cfg(test)]
mod compliance_tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_format_packed() {
        let webauthn = create_test_webauthn();
        let attestation = create_packed_attestation();
        
        let result = webauthn.verify_attestation(&attestation).await;
        
        assert!(result.is_ok());
        // Verify attestation format is correctly identified
        let credential = result.unwrap();
        assert_eq!(credential.attestation_type, "packed");
    }

    #[tokio::test]
    async fn test_attestation_format_fido_u2f() {
        let webauthn = create_test_webauthn();
        let attestation = create_fido_u2f_attestation();
        
        let result = webauthn.verify_attestation(&attestation).await;
        
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert_eq!(credential.attestation_type, "fido-u2f");
    }

    #[tokio::test]
    async fn test_attestation_format_none() {
        let webauthn = create_test_webauthn();
        let attestation = create_none_attestation();
        
        let result = webauthn.verify_attestation(&attestation).await;
        
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert_eq!(credential.attestation_type, "none");
    }

    #[tokio::test]
    async fn test_invalid_attestation_format() {
        let webauthn = create_test_webauthn();
        let attestation = create_invalid_attestation();
        
        let result = webauthn.verify_attestation(&attestation).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UnsupportedFormat));
    }
}
```

### 4.2 Vulnerability Tests

#### Replay Attack Tests
```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[tokio::test]
    async fn test_replay_attack_prevention() {
        let test_app = TestApp::new().await;

        // Step 1: Get challenge
        let options_resp = get_attestation_options(&test_app, "testuser").await;
        let challenge = extract_challenge(&options_resp).await;

        // Step 2: Create valid attestation
        let attestation = create_valid_attestation(&challenge);
        let result_resp = submit_attestation(&test_app, &attestation).await;
        assert_eq!(result_resp.status(), 200);

        // Step 3: Try to replay the same attestation
        let replay_resp = submit_attestation(&test_app, &attestation).await;
        assert_eq!(replay_resp.status(), 400);
        
        let error_body: serde_json::Value = replay_resp.json().await.unwrap();
        assert!(error_body["errorMessage"].as_str().unwrap().contains("challenge"));
    }

    #[tokio::test]
    async fn test_expired_challenge() {
        let test_app = TestApp::new().await;

        // Create an expired challenge
        let expired_challenge = create_expired_challenge(&test_app.db_pool).await;
        let attestation = create_valid_attestation(&expired_challenge);

        let result_resp = submit_attestation(&test_app, &attestation).await;
        assert_eq!(result_resp.status(), 400);
        
        let error_body: serde_json::Value = result_resp.json().await.unwrap();
        assert!(error_body["errorMessage"].as_str().unwrap().contains("expired"));
    }

    #[tokio::test]
    async fn test_origin_validation() {
        let test_app = TestApp::new().await;

        // Create attestation with invalid origin
        let attestation = create_attestation_with_invalid_origin();
        let result_resp = submit_attestation(&test_app, &attestation).await;
        
        assert_eq!(result_resp.status(), 400);
        
        let error_body: serde_json::Value = result_resp.json().await.unwrap();
        assert!(error_body["errorMessage"].as_str().unwrap().contains("origin"));
    }

    #[tokio::test]
    async fn test_credential_enumeration_prevention() {
        let test_app = TestApp::new().await;

        // Try to authenticate with non-existent user
        let options_request = serde_json::json!({
            "username": "nonexistentuser",
            "userVerification": "preferred"
        });

        let options_resp = test_app
            .app
            .post("/assertion/options")
            .send_json(&options_request)
            .await
            .unwrap();

        // Should return success with empty allowCredentials
        assert_eq!(options_resp.status(), 200);
        let options_body: serde_json::Value = options_resp.json().await.unwrap();
        assert!(options_body["allowCredentials"].as_array().unwrap().is_empty());
    }
}
```

### 4.3 Rate Limiting Tests
```rust
#[tokio::test]
async fn test_rate_limiting() {
    let test_app = TestApp::new().await;

    // Make multiple rapid requests
    let mut responses = Vec::new();
    for _ in 0..100 {
        let resp = test_app
            .app
            .post("/attestation/options")
            .send_json(&serde_json::json!({
                "username": "testuser",
                "displayName": "Test User"
            }))
            .await
            .unwrap();
        responses.push(resp.status());
    }

    // Should have some rate limited responses
    let rate_limited_count = responses.iter().filter(|&&status| status == 429).count();
    assert!(rate_limited_count > 0);
}
```

## 5. Performance Testing Strategy

### 5.1 Load Testing
```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn test_concurrent_registrations() {
        let test_app = TestApp::new().await;
        let concurrent_users = 100;
        let start_time = Instant::now();

        let mut tasks = JoinSet::new();
        
        for i in 0..concurrent_users {
            let app = test_app.app.clone();
            tasks.spawn(async move {
                let username = format!("user{}", i);
                let request = serde_json::json!({
                    "username": username,
                    "displayName": format!("User {}", i),
                    "attestation": "none"
                });

                let resp = app
                    .post("/attestation/options")
                    .send_json(&request)
                    .await
                    .unwrap();
                
                resp.status()
            });
        }

        let mut success_count = 0;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(status) if status == 200 => success_count += 1,
                _ => {}
            }
        }

        let elapsed = start_time.elapsed();
        
        // Performance assertions
        assert!(success_count >= concurrent_users * 95 / 100); // 95% success rate
        assert!(elapsed < Duration::from_secs(10)); // Under 10 seconds
        println!("Processed {} requests in {:?}", success_count, elapsed);
    }

    #[tokio::test]
    async fn test_authentication_response_time() {
        let test_app = TestApp::new().await;
        
        // Register a credential first
        let credential_id = register_test_credential(&test_app).await;

        let iterations = 1000;
        let mut total_time = Duration::ZERO;

        for _ in 0..iterations {
            let start = Instant::now();
            
            // Get assertion options
            let options_resp = test_app
                .app
                .post("/assertion/options")
                .send_json(&serde_json::json!({
                    "username": "testuser",
                    "userVerification": "preferred"
                }))
                .await
                .unwrap();

            let options_body: serde_json::Value = options_resp.json().await.unwrap();
            let challenge = options_body["challenge"].as_str().unwrap();

            // Submit assertion
            let assertion = create_mock_assertion_response(challenge, &credential_id);
            let _result_resp = test_app
                .app
                .post("/assertion/result")
                .send_json(&assertion)
                .await
                .unwrap();

            total_time += start.elapsed();
        }

        let average_time = total_time / iterations;
        assert!(average_time < Duration::from_millis(100)); // Under 100ms average
        println!("Average authentication time: {:?}", average_time);
    }
}
```

## 6. Property-Based Testing

### 6.1 Input Validation Tests
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_username_validation_property(
        username in "[a-zA-Z0-9@._-]{3,64}"
    ) {
        prop_assert!(validate_username(&username).is_ok());
    }

    #[test]
    fn test_invalid_username_property(
        invalid_username in prop::string::string_regex(r".{0,2}|.{65,}|[^\w@._-]").unwrap()
    ) {
        prop_assert!(validate_username(&invalid_username).is_err());
    }

    #[test]
    fn test_credential_id_validation_property(
        credential_id in "[A-Za-z0-9_-]{1,1024}"
    ) {
        // Test valid base64url strings
        if is_valid_base64url(&credential_id) {
            prop_assert!(validate_credential_id(&credential_id).is_ok());
        }
    }
}
```

## 7. Test Data Management

### 7.1 Test Fixtures
```rust
pub mod fixtures {
    use super::*;
    use webauthn_rs::prelude::*;

    pub fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            user_handle: generate_random_bytes(32),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn create_test_credential() -> Credential {
        Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: generate_random_bytes(32),
            credential_public_key: generate_random_bytes(32),
            attestation_type: "none".to_string(),
            aaguid: Some(generate_random_bytes(16)),
            sign_count: 0,
            user_verified: false,
            backup_eligible: false,
            backup_state: false,
            transports: Some(vec!["internal".to_string()]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used: None,
        }
    }

    pub fn create_valid_attestation(challenge: &str) -> AttestationResponse {
        // Create a valid attestation response for testing
        AttestationResponse {
            id: base64url::encode(&generate_random_bytes(32)),
            raw_id: base64url::encode(&generate_random_bytes(32)),
            response: AttestationResponseData {
                attestation_object: create_mock_attestation_object(challenge),
                client_data_json: create_mock_client_data_json(challenge, "webauthn.create"),
            },
            type_: "public-key".to_string(),
            client_extension_results: serde_json::json!({}),
        }
    }

    fn create_mock_attestation_object(challenge: &str) -> String {
        // Create a mock attestation object for testing
        // This would contain proper CBOR-encoded data
        format!("mock_attestation_object_{}", challenge)
    }

    fn create_mock_client_data_json(challenge: &str, typ: &str) -> String {
        serde_json::json!({
            "type": typ,
            "challenge": challenge,
            "origin": "https://localhost:8443",
            "crossOrigin": false
        }).to_string()
    }
}
```

## 8. Continuous Integration Testing

### 8.1 GitHub Actions Configuration
```yaml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: testdb
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
    
    - name: Run formatting check
      run: cargo fmt -- --check
    
    - name: Run clippy
      run: cargo clippy -- -D warnings
    
    - name: Run unit tests
      run: cargo test --lib
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/testdb
    
    - name: Run integration tests
      run: cargo test --test '*'
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/testdb
    
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml --output-dir ./coverage
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/cobertura.xml

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run security audit
      run: cargo audit
    
    - name: Run dependency check
      run: cargo deny check

  performance:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run performance tests
      run: cargo test --release performance_tests
```

## 9. Test Reporting and Metrics

### 9.1 Coverage Reporting
```bash
# Generate coverage report
cargo tarpaulin --out Html --output-dir ./coverage

# Generate coverage badge
cargo tarpaulin --out Xml --output-dir ./coverage
```

### 9.2 Performance Benchmarking
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_attestation_verification(c: &mut Criterion) {
    let webauthn = create_test_webauthn();
    let attestation = create_valid_attestation();

    c.bench_function("attestation_verification", |b| {
        b.iter(|| {
            webauthn.verify_attestation(black_box(&attestation))
        })
    });
}

fn benchmark_assertion_verification(c: &mut Criterion) {
    let webauthn = create_test_webauthn();
    let assertion = create_valid_assertion();

    c.bench_function("assertion_verification", |b| {
        b.iter(|| {
            webauthn.verify_assertion(black_box(&assertion))
        })
    });
}

criterion_group!(
    benches,
    benchmark_attestation_verification,
    benchmark_assertion_verification
);
criterion_main!(benches);
```

This comprehensive testing strategy ensures that the FIDO2/WebAuthn server is secure, compliant, and reliable through extensive automated testing at all levels.