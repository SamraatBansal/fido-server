# FIDO2/WebAuthn Server - Test Specification

## Overview

This document provides a comprehensive testing specification for the FIDO2/WebAuthn Relying Party Server, covering unit tests, integration tests, security tests, and compliance verification.

## 1. Unit Testing Strategy

### 1.1 WebAuthn Service Tests

#### Challenge Generation Tests
```rust
#[cfg(test)]
mod challenge_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_challenge_generation_entropy() {
        // Test that challenges have sufficient entropy
        let challenge = generate_challenge();
        assert_eq!(challenge.len(), 32); // 256 bits
        // Verify randomness by generating multiple challenges
        let challenges: Vec<_> = (0..100).map(|_| generate_challenge()).collect();
        let unique_challenges: HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), 100);
    }

    #[test]
    fn test_challenge_base64url_encoding() {
        let challenge = generate_challenge();
        let encoded = base64url_encode(&challenge);
        // Verify no padding characters
        assert!(!encoded.contains('='));
        // Verify valid base64url characters only
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    proptest! {
        #[test]
        fn test_challenge_uniqueness(
            count in 1..1000usize
        ) {
            let challenges: Vec<_> = (0..count).map(|_| generate_challenge()).collect();
            let unique: HashSet<_> = challenges.iter().collect();
            prop_assert_eq!(unique.len(), count);
        }
    }
}
```

#### Attestation Validation Tests
```rust
#[cfg(test)]
mod attestation_tests {
    use super::*;

    #[test]
    fn test_packed_attestation_validation() {
        // Test valid packed attestation
        let valid_attestation = create_valid_packed_attestation();
        let result = validate_attestation(&valid_attestation).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_attestation_signature() {
        let mut attestation = create_valid_packed_attestation();
        // Corrupt signature
        attestation.signature = vec![0u8; 64];
        let result = validate_attestation(&attestation).await;
        assert!(matches!(result, Err(WebAuthnError::InvalidSignature)));
    }

    #[test]
    fn test_unsupported_attestation_format() {
        let unsupported_attestation = create_unsupported_attestation();
        let result = validate_attestation(&unsupported_attestation).await;
        assert!(matches!(result, Err(WebAuthnError::UnsupportedFormat)));
    }

    #[test]
    fn test_attestation_rp_id_mismatch() {
        let mut attestation = create_valid_packed_attestation();
        attestation.rp_id = "malicious.com".to_string();
        let result = validate_attestation(&attestation).await;
        assert!(matches!(result, Err(WebAuthnError::RpIdMismatch)));
    }
}
```

#### Assertion Validation Tests
```rust
#[cfg(test)]
mod assertion_tests {
    use super::*;

    #[test]
    fn test_valid_assertion_verification() {
        let assertion = create_valid_assertion();
        let credential = get_test_credential();
        let result = verify_assertion(&assertion, &credential).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_assertion_counter_regression() {
        let mut assertion = create_valid_assertion();
        assertion.authenticator_data.sign_count = 10;
        let mut credential = get_test_credential();
        credential.sign_count = 20; // Higher than assertion
        
        let result = verify_assertion(&assertion, &credential).await;
        assert!(matches!(result, Err(WebAuthnError::CounterRegression)));
    }

    #[test]
    fn test_expired_challenge() {
        let mut assertion = create_valid_assertion();
        assertion.challenge = create_expired_challenge();
        let credential = get_test_credential();
        
        let result = verify_assertion(&assertion, &credential).await;
        assert!(matches!(result, Err(WebAuthnError::ExpiredChallenge)));
    }
}
```

### 1.2 Database Repository Tests

#### User Repository Tests
```rust
#[cfg(test)]
mod user_repository_tests {
    use super::*;
    use diesel::connection::Connection;
    use diesel::r2d2::ConnectionManager;

    #[test]
    fn test_create_user() {
        let conn = establish_test_connection();
        let user = NewUser {
            username: "test@example.com",
            display_name: "Test User",
            user_handle: generate_user_handle(),
        };

        let created_user = UserRepository::create(&conn, &user).unwrap();
        assert_eq!(created_user.username, user.username);
        assert!(created_user.id.is_some());
    }

    #[test]
    fn test_duplicate_username_prevention() {
        let conn = establish_test_connection();
        let user = create_test_user(&conn);
        
        let duplicate_user = NewUser {
            username: user.username.clone(),
            display_name: "Different User",
            user_handle: generate_user_handle(),
        };

        let result = UserRepository::create(&conn, &duplicate_user);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_lookup_by_username() {
        let conn = establish_test_connection();
        let user = create_test_user(&conn);
        
        let found_user = UserRepository::find_by_username(&conn, &user.username).unwrap();
        assert_eq!(found_user.id, user.id);
    }

    #[test]
    fn test_user_not_found() {
        let conn = establish_test_connection();
        let result = UserRepository::find_by_username(&conn, "nonexistent@example.com");
        assert!(result.is_err());
    }
}
```

#### Credential Repository Tests
```rust
#[cfg(test)]
mod credential_repository_tests {
    use super::*;

    #[test]
    fn test_create_credential() {
        let conn = establish_test_connection();
        let user = create_test_user(&conn);
        let credential = create_test_credential_data(user.id);

        let created = CredentialRepository::create(&conn, &credential).unwrap();
        assert_eq!(created.user_id, credential.user_id);
        assert_eq!(created.credential_id, credential.credential_id);
    }

    #[test]
    fn test_duplicate_credential_id_prevention() {
        let conn = establish_test_connection();
        let user = create_test_user(&conn);
        let credential = create_test_credential_data(user.id);
        let created = CredentialRepository::create(&conn, &credential).unwrap();

        let duplicate_credential = NewCredential {
            user_id: user.id,
            credential_id: created.credential_id.clone(),
            ..Default::default()
        };

        let result = CredentialRepository::create(&conn, &duplicate_credential);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_credentials_by_user() {
        let conn = establish_test_connection();
        let user = create_test_user(&conn);
        
        // Create multiple credentials for the user
        let cred1 = create_test_credential_data(user.id);
        let cred2 = create_test_credential_data(user.id);
        CredentialRepository::create(&conn, &cred1).unwrap();
        CredentialRepository::create(&conn, &cred2).unwrap();

        let credentials = CredentialRepository::find_by_user_id(&conn, user.id).unwrap();
        assert_eq!(credentials.len(), 2);
    }
}
```

### 1.3 Controller Tests

#### Registration Controller Tests
```rust
#[cfg(test)]
mod registration_controller_tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_registration_challenge_success() {
        let app = test::init_service(
            App::new()
                .configure(routes::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/v1/registration/challenge")
            .set_json(&RegistrationChallengeRequest {
                username: "test@example.com".to_string(),
                display_name: "Test User".to_string(),
                user_verification: "preferred".to_string(),
                attestation: "none".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let response: RegistrationChallengeResponse = 
            test::read_body_json(resp).await;
        assert!(!response.challenge.is_empty());
        assert_eq!(response.rp.id, "localhost");
        assert_eq!(response.user.name, "test@example.com");
    }

    #[actix_web::test]
    async fn test_registration_challenge_invalid_email() {
        let app = test::init_service(
            App::new()
                .configure(routes::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/v1/registration/challenge")
            .set_json(&RegistrationChallengeRequest {
                username: "invalid-email".to_string(),
                display_name: "Test User".to_string(),
                user_verification: "preferred".to_string(),
                attestation: "none".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn test_registration_verify_success() {
        let app = test::init_service(
            App::new()
                .configure(routes::configure)
        ).await;

        // First, create a challenge
        let challenge_req = RegistrationChallengeRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: "preferred".to_string(),
            attestation: "none".to_string(),
        };

        let challenge_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/registration/challenge")
                .set_json(&challenge_req)
                .to_request()
        ).await;

        let challenge: RegistrationChallengeResponse = 
            test::read_body_json(challenge_resp).await;

        // Now verify the attestation
        let verify_req = RegistrationVerifyRequest {
            credential: create_mock_attestation(),
            session_data: RegistrationSessionData {
                challenge: challenge.challenge.clone(),
                username: "test@example.com".to_string(),
            },
        };

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/v1/registration/verify")
                .set_json(&verify_req)
                .to_request()
        ).await;

        assert_eq!(resp.status(), 200);
    }
}
```

## 2. Integration Testing Strategy

### 2.1 End-to-End Flow Tests

#### Complete Registration Flow
```rust
#[cfg(test)]
mod e2e_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_registration_flow() {
        let server = start_test_server().await;
        let client = WebAuthnClient::new(server.url());

        // Step 1: Request registration challenge
        let challenge = client
            .request_registration_challenge(&RegistrationRequest {
                username: "user@example.com",
                display_name: "Test User",
            })
            .await
            .expect("Failed to get registration challenge");

        // Step 2: Create credential with authenticator
        let credential = MockAuthenticator::create_credential(&challenge).await;

        // Step 3: Complete registration
        let result = client
            .complete_registration(&RegistrationCompletion {
                credential,
                session_data: challenge.session_data,
            })
            .await
            .expect("Failed to complete registration");

        assert!(!result.credential_id.is_empty());
        assert!(result.user_verified);
    }

    #[tokio::test]
    async fn test_complete_authentication_flow() {
        let server = start_test_server().await;
        let client = WebAuthnClient::new(server.url());

        // First, register a user
        let user = register_test_user(&client).await;

        // Step 1: Request authentication challenge
        let challenge = client
            .request_authentication_challenge(&AuthenticationRequest {
                username: user.username,
            })
            .await
            .expect("Failed to get authentication challenge");

        // Step 2: Create assertion with authenticator
        let assertion = MockAuthenticator::create_assertion(&challenge, &user.credential_id).await;

        // Step 3: Complete authentication
        let result = client
            .complete_authentication(&AuthenticationCompletion {
                assertion,
                session_data: challenge.session_data,
            })
            .await
            .expect("Failed to complete authentication");

        assert!(result.user_verified);
        assert!(result.new_sign_count > 0);
    }
}
```

### 2.2 Database Integration Tests

#### Transaction Handling Tests
```rust
#[cfg(test)]
mod db_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_user_credential_transaction() {
        let pool = create_test_db_pool().await;
        let mut conn = pool.get().await.unwrap();

        // Test transaction rollback on error
        let result = conn.transaction::<_, Error, _>(|conn| {
            let user = create_test_user_in_transaction(conn)?;
            let credential = create_test_credential_in_transaction(conn, user.id)?;
            
            // Simulate an error
            Err(Error::DatabaseError("Simulated error".to_string()))
        }).await;

        assert!(result.is_err());
        
        // Verify rollback - user should not exist
        let user_count = diesel::select(diesel::dsl::count(users::id))
            .first::<i64>(&mut conn)
            .await
            .unwrap();
        assert_eq!(user_count, 0);
    }

    #[tokio::test]
    async fn test_concurrent_credential_creation() {
        let pool = create_test_db_pool().await;
        let user = create_test_user(&pool).await;

        // Spawn multiple concurrent credential creation tasks
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let pool = pool.clone();
                let user_id = user.id;
                tokio::spawn(async move {
                    let mut conn = pool.get().await.unwrap();
                    let credential = create_test_credential_data(user_id);
                    CredentialRepository::create(&mut conn, &credential).await
                })
            })
            .collect();

        // Wait for all tasks to complete
        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .collect();

        // Only one should succeed due to unique constraint
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 1);
    }
}
```

## 3. Security Testing Strategy

### 3.1 Vulnerability Tests

#### Replay Attack Tests
```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_reuse_prevention() {
        let server = start_test_server().await;
        let client = WebAuthnClient::new(server.url());

        // Get a challenge
        let challenge = client
            .request_registration_challenge(&RegistrationRequest {
                username: "test@example.com",
                display_name: "Test User",
            })
            .await
            .unwrap();

        // Create credential
        let credential = MockAuthenticator::create_credential(&challenge).await;

        // Complete registration first time
        let result1 = client
            .complete_registration(&RegistrationCompletion {
                credential: credential.clone(),
                session_data: challenge.session_data.clone(),
            })
            .await;
        assert!(result1.is_ok());

        // Try to use the same challenge again
        let result2 = client
            .complete_registration(&RegistrationCompletion {
                credential,
                session_data: challenge.session_data,
            })
            .await;
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), WebAuthnError::ChallengeAlreadyUsed));
    }

    #[tokio::test]
    async fn test_malformed_attestation_handling() {
        let server = start_test_server().await;
        let client = WebAuthnClient::new(server.url());

        let challenge = client
            .request_registration_challenge(&RegistrationRequest {
                username: "test@example.com",
                display_name: "Test User",
            })
            .await
            .unwrap();

        // Send malformed attestation
        let malformed_credential = AttestationCredential {
            id: "invalid-base64".to_string(),
            raw_id: "invalid-base64".to_string(),
            response: AttestationResponse {
                attestation_object: "invalid-base64".to_string(),
                client_data_json: "invalid-json".to_string(),
            },
            r#type: "public-key".to_string(),
        };

        let result = client
            .complete_registration(&RegistrationCompletion {
                credential: malformed_credential,
                session_data: challenge.session_data,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidFormat));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let server = start_test_server().await;
        let client = WebAuthnClient::new(server.url());

        // Make rapid requests to trigger rate limiting
        let mut success_count = 0;
        for _ in 0..100 {
            let result = client
                .request_registration_challenge(&RegistrationRequest {
                    username: "test@example.com",
                    display_name: "Test User",
                })
                .await;

            if result.is_ok() {
                success_count += 1;
            } else {
                break;
            }
        }

        // Should be rate limited after some requests
        assert!(success_count < 100);
    }
}
```

### 3.2 Cryptographic Tests

#### Signature Verification Tests
```rust
#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_es256_signature_verification() {
        let key_pair = generate_es256_keypair();
        let message = b"test message";
        let signature = sign_es256(&key_pair.private_key, message);

        let result = verify_es256_signature(
            &key_pair.public_key,
            message,
            &signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_rejection() {
        let key_pair = generate_es256_keypair();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = sign_es256(&key_pair.private_key, wrong_message);

        let result = verify_es256_signature(
            &key_pair.public_key,
            message,
            &signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_random_number_quality() {
        // Test that random numbers have sufficient entropy
        let samples: Vec<[u8; 32]> = (0..1000)
            .map(|_| generate_secure_random())
            .collect();

        // Check for duplicates (should be extremely unlikely)
        let unique: HashSet<_> = samples.iter().collect();
        assert_eq!(unique.len(), 1000);

        // Basic statistical tests
        let mut bit_counts = [0; 8];
        for sample in &samples {
            for byte in sample {
                for i in 0..8 {
                    if (byte >> i) & 1 == 1 {
                        bit_counts[i] += 1;
                    }
                }
            }
        }

        // Each bit should be set approximately 50% of the time
        let total_bits = samples.len() * 32;
        for count in &bit_counts {
            let ratio = *count as f64 / total_bits as f64;
            assert!((0.45..0.55).contains(&ratio));
        }
    }
}
```

## 4. Compliance Testing Strategy

### 4.1 FIDO2 Conformance Tests

#### WebAuthn Level 2 Tests
```rust
#[cfg(test)]
mod compliance_tests {
    use super::*;

    #[tokio::test]
    async fn test_rp_id_validation() {
        let test_cases = vec![
            ("localhost", "https://localhost", true),
            ("example.com", "https://example.com", true),
            ("sub.example.com", "https://example.com", false),
            ("evil.com", "https://localhost", false),
        ];

        for (rp_id, origin, should_pass) in test_cases {
            let result = validate_rp_id(rp_id, origin);
            assert_eq!(result.is_ok(), should_pass);
        }
    }

    #[tokio::test]
    async fn test_attestation_format_compliance() {
        let supported_formats = vec!["packed", "fido-u2f", "none"];
        
        for format in supported_formats {
            let attestation = create_attestation_with_format(format);
            let result = validate_attestation(&attestation).await;
            assert!(result.is_ok(), "Format {} should be supported", format);
        }

        // Test unsupported format
        let unsupported_attestation = create_attestation_with_format("unsupported");
        let result = validate_attestation(&unsupported_attestation).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_verification_enforcement() {
        let test_cases = vec![
            ("required", true, true),
            ("required", false, false),
            ("preferred", true, true),
            ("preferred", false, true),
            ("discouraged", true, true),
            ("discouraged", false, true),
        ];

        for (requirement, user_verified, should_pass) in test_cases {
            let assertion = create_assertion_with_user_verification(user_verified);
            let result = verify_user_verification(&assertion, requirement);
            assert_eq!(result.is_ok(), should_pass);
        }
    }
}
```

### 4.2 Performance Tests

#### Load Testing
```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use criterion::{black_box, criterion_group, criterion_main, Criterion};

    fn benchmark_challenge_generation(c: &mut Criterion) {
        c.bench_function("generate_challenge", |b| {
            b.iter(|| {
                black_box(generate_challenge())
            })
        });
    }

    fn benchmark_attestation_validation(c: &mut Criterion) {
        let attestation = create_valid_packed_attestation();
        
        c.bench_function("validate_attestation", |b| {
            b.iter(|| {
                black_box(validate_attestation(black_box(&attestation)))
            })
        });
    }

    #[tokio::test]
    async fn test_concurrent_registration_load() {
        let server = start_test_server().await;
        let client = WebAuthnClient::new(server.url());

        let concurrent_requests = 100;
        let handles: Vec<_> = (0..concurrent_requests)
            .map(|i| {
                let client = client.clone();
                tokio::spawn(async move {
                    let username = format!("user{}@example.com", i);
                    client
                        .request_registration_challenge(&RegistrationRequest {
                            username,
                            display_name: format!("User {}", i),
                        })
                        .await
                })
            })
            .collect();

        let results = futures::future::join_all(handles).await;
        let success_count = results.iter().filter(|r| {
            matches!(r, Ok(Ok(_)))
        }).count();

        // At least 95% should succeed under normal load
        assert!(success_count >= concurrent_requests * 95 / 100);
    }

    criterion_group!(
        benches,
        benchmark_challenge_generation,
        benchmark_attestation_validation
    );
    criterion_main!(benches);
}
```

## 5. Test Data Management

### 5.1 Test Fixtures

#### Mock Data Generators
```rust
#[cfg(test)]
pub mod fixtures {
    use super::*;
    use fake::{Fake, Faker};
    use rand::Rng;

    pub fn generate_test_user() -> NewUser {
        NewUser {
            username: format!("user{}@example.com", rand::thread_rng().gen_range(1000..9999)),
            display_name: format!("Test User {}", rand::thread_rng().gen_range(1000..9999)),
            user_handle: generate_user_handle(),
        }
    }

    pub fn generate_test_credential(user_id: Uuid) -> NewCredential {
        NewCredential {
            user_id,
            credential_id: generate_credential_id(),
            public_key: generate_public_key(),
            sign_count: 0,
            aaguid: Some(generate_aaguid()),
            attestation_format: "packed".to_string(),
            backup_eligible: false,
            backup_state: false,
            transports: Some(vec!["internal".to_string()]),
        }
    }

    pub fn create_mock_attestation() -> AttestationCredential {
        AttestationCredential {
            id: base64url_encode(&generate_credential_id()),
            raw_id: base64url_encode(&generate_credential_id()),
            response: AttestationResponse {
                attestation_object: base64url_encode(&create_mock_attestation_object()),
                client_data_json: base64url_encode(&create_mock_client_data()),
            },
            r#type: "public-key".to_string(),
        }
    }

    fn create_mock_attestation_object() -> Vec<u8> {
        // Create a valid CBOR-encoded attestation object
        // This would contain authenticator data, attestation statement, etc.
        cbor::to_vec(&AttestationObject {
            fmt: "packed".to_string(),
            auth_data: create_authenticator_data(),
            att_stmt: create_attestation_statement(),
        }).unwrap()
    }

    fn create_mock_client_data() -> Vec<u8> {
        serde_json::to_vec(&ClientData {
            type: "webauthn.create".to_string(),
            challenge: base64url_encode(&generate_challenge()),
            origin: "https://localhost".to_string(),
            cross_origin: false,
        }).unwrap()
    }
}
```

### 5.2 Test Database Setup

#### Database Utilities
```rust
#[cfg(test)]
pub mod test_db {
    use super::*;
    use diesel::r2d2::{ConnectionManager, Pool};

    pub async fn create_test_db_pool() -> Pool<ConnectionManager<PgConnection>> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/fido_server_test".to_string());

        let manager = ConnectionManager::<PgConnection>::new(database_url);
        Pool::builder()
            .max_size(5)
            .build(manager)
            .expect("Failed to create test database pool")
    }

    pub async fn setup_test_database(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut conn = pool.get().await.unwrap();
        
        // Run migrations
        diesel_migrations::run_pending_migrations(&mut conn)
            .expect("Failed to run test migrations");

        // Clean up any existing data
        diesel::delete(credential::table)
            .execute(&mut conn)
            .unwrap();
        diesel::delete(user::table)
            .execute(&mut conn)
            .unwrap();
        diesel::delete(challenge::table)
            .execute(&mut conn)
            .unwrap();
    }

    pub fn establish_test_connection() -> PgConnection {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/fido_server_test".to_string());
        
        PgConnection::establish(&database_url)
            .expect("Failed to establish test database connection")
    }
}
```

## 6. Test Execution and CI/CD

### 6.1 Test Configuration

#### Cargo.toml Test Configuration
```toml
[dev-dependencies]
# Testing Framework
tokio-test = "0.4"
actix-test = "0.1"
mockall = "0.13"
tempfile = "3.10"

# Property-based Testing
proptest = "1.4"
quickcheck = "1.0"
quickcheck_macros = "1.0"

# Test Data Generation
fake = { version = "2.9", features = ["derive"] }
rand = "0.8"

# Benchmarking
criterion = { version = "0.5", features = ["html_reports"] }

# Database Testing
diesel_migrations = "2.1"

# Security Testing
webauthn-rs = { version = "0.5", features = ["danger-allow-insecure"] }

[[bench]]
name = "webauthn_benchmarks"
harness = false

[profile.bench]
debug = true
```

### 6.2 GitHub Actions Workflow

#### .github/workflows/test.yml
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
          POSTGRES_DB: fido_server_test
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
      
    - name: Setup database
      run: |
        diesel database setup --database-url postgres://postgres:postgres@localhost/fido_server_test
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost/fido_server_test
        
    - name: Run formatting check
      run: cargo fmt --all -- --check
      
    - name: Run clippy
      run: cargo clippy --all-targets --all-features -- -D warnings
      
    - name: Run unit tests
      run: cargo test --lib
      env:
        TEST_DATABASE_URL: postgres://postgres:postgres@localhost/fido_server_test
        
    - name: Run integration tests
      run: cargo test --test '*'
      env:
        TEST_DATABASE_URL: postgres://postgres:postgres@localhost/fido_server_test
        
    - name: Run benchmarks
      run: cargo bench
      env:
        TEST_DATABASE_URL: postgres://postgres:postgres@localhost/fido_server_test
        
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml --output-dir ./coverage
      env:
        TEST_DATABASE_URL: postgres://postgres:postgres@localhost/fido_server_test
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/cobertura.xml
        flags: unittests
        name: codecov-umbrella

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run security audit
      run: cargo audit
      
    - name: Run cargo-deny
      uses: EmbarkStudios/cargo-deny-action@v1
```

## 7. Test Coverage Requirements

### 7.1 Coverage Metrics

#### Target Coverage Levels
- **Unit Tests**: 95% line coverage, 90% branch coverage
- **Integration Tests**: 100% API endpoint coverage
- **Security Tests**: 100% critical security function coverage
- **Compliance Tests**: 100% FIDO2 specification requirement coverage

#### Coverage Exclusions
- Test modules and test utilities
- Error handling paths that are unreachable
- Generated code and macros
- Third-party dependency code

### 7.2 Coverage Reporting

#### Tarpaulin Configuration
```toml
# .tarpaulin.toml
[report]
out = ["Xml", "Html", "Json"]
output-dir = "./coverage"
exclude-files = ["tests/*", "src/main.rs"]

[engine]
hardlink = false

[coverage]
run-types = ["Tests", "Doctests"]
ignore-panics = true
fail-under = 95
```

This comprehensive test specification ensures thorough testing of all aspects of the FIDO2/WebAuthn server implementation, with particular focus on security, compliance, and reliability.