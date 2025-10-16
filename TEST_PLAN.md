# FIDO2/WebAuthn Server - Comprehensive Test Plan

## Overview

This test plan provides detailed testing strategies and test cases for the FIDO2/WebAuthn Relying Party Server implementation. The plan covers unit tests, integration tests, security tests, and compliance verification to ensure robust and secure implementation.

## 1. Testing Strategy

### 1.1 Test Pyramid

```
    E2E Tests (5%)
   ┌─────────────────┐
  │  Integration    │ (25%)
 ┌─────────────────────┐
│    Unit Tests       │ (70%)
└─────────────────────┘
```

### 1.2 Test Categories

#### Unit Tests (70%)
- Individual function testing
- Business logic validation
- Error handling verification
- Data transformation testing

#### Integration Tests (25%)
- API endpoint testing
- Database integration testing
- Service layer integration
- Middleware testing

#### End-to-End Tests (5%)
- Complete user flows
- Cross-system integration
- Performance testing
- Security testing

### 1.3 Testing Tools and Frameworks

#### Unit Testing
- `cargo test` - Built-in Rust testing
- `mockall` - Mocking framework
- `proptest` - Property-based testing
- `quickcheck` - Randomized testing

#### Integration Testing
- `actix-test` - HTTP testing
- `testcontainers` - Database testing
- `wiremock` - HTTP service mocking
- `tempfile` - Temporary file testing

#### Security Testing
- Custom security test suites
- FIDO2 compliance test tools
- Penetration testing scripts
- Vulnerability scanning

## 2. Unit Test Specifications

### 2.1 WebAuthn Service Tests

#### Challenge Generation Tests
```rust
#[cfg(test)]
mod challenge_tests {
    use super::*;
    use proptest::prelude::*;
    
    #[test]
    fn test_challenge_generation_length() {
        // Test that generated challenges are at least 16 bytes
        let challenge = generate_challenge();
        assert!(challenge.len() >= 16);
    }
    
    #[test]
    fn test_challenge_uniqueness() {
        // Test that multiple challenges are unique
        let challenges: Vec<_> = (0..100).map(|_| generate_challenge()).collect();
        let unique_challenges: HashSet<_> = challenges.iter().collect();
        assert_eq!(challenges.len(), unique_challenges.len());
    }
    
    #[test]
    fn test_challenge_encoding() {
        // Test Base64URL encoding without padding
        let challenge = generate_challenge();
        let encoded = base64url_encode(&challenge);
        assert!(!encoded.ends_with('='));
        assert!(encoded.is_ascii());
    }
    
    proptest! {
        #[test]
        fn test_challenge_randomness(_ in 0..1000) {
            let challenge = generate_challenge();
            // Test that challenge contains sufficient entropy
            let entropy = calculate_entropy(&challenge);
            assert!(entropy >= 7.0); // At least 7 bits of entropy per byte
        }
    }
}
```

#### Attestation Verification Tests
```rust
#[cfg(test)]
mod attestation_tests {
    use super::*;
    
    #[test]
    fn test_packed_attestation_validation() {
        // Test valid packed attestation
        let valid_attestation = create_valid_packed_attestation();
        let result = verify_attestation(&valid_attestation);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_fido_u2f_attestation_validation() {
        // Test valid FIDO-U2F attestation
        let valid_attestation = create_valid_fido_u2f_attestation();
        let result = verify_attestation(&valid_attestation);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_none_attestation_validation() {
        // Test none attestation (no attestation)
        let none_attestation = create_none_attestation();
        let result = verify_attestation(&none_attestation);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_invalid_attestation_signature() {
        // Test attestation with invalid signature
        let invalid_attestation = create_attestation_with_invalid_signature();
        let result = verify_attestation(&invalid_attestation);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidSignature));
    }
    
    #[test]
    fn test_invalid_attestation_format() {
        // Test unsupported attestation format
        let invalid_format = create_invalid_format_attestation();
        let result = verify_attestation(&invalid_format);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UnsupportedFormat));
    }
}
```

#### Assertion Verification Tests
```rust
#[cfg(test)]
mod assertion_tests {
    use super::*;
    
    #[test]
    fn test_valid_assertion_verification() {
        // Test valid assertion with proper signature
        let valid_assertion = create_valid_assertion();
        let credential = get_test_credential();
        let result = verify_assertion(&valid_assertion, &credential);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_invalid_assertion_signature() {
        // Test assertion with invalid signature
        let invalid_assertion = create_assertion_with_invalid_signature();
        let credential = get_test_credential();
        let result = verify_assertion(&invalid_assertion, &credential);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_assertion_counter_increment() {
        // Test that sign counter is properly validated
        let mut credential = get_test_credential();
        credential.sign_count = 10;
        
        let assertion = create_assertion_with_counter(5); // Lower counter
        let result = verify_assertion(&assertion, &credential);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidCounter));
    }
    
    #[test]
    fn test_user_verification_flag() {
        // Test UV flag validation
        let assertion = create_assertion_without_uv();
        let credential = get_test_credential();
        let result = verify_assertion(&assertion, &credential);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UserVerificationRequired));
    }
}
```

### 2.2 Database Layer Tests

#### Repository Tests
```rust
#[cfg(test)]
mod repository_tests {
    use super::*;
    use testcontainers::clients::Cli;
    use testcontainers::images::postgres::Postgres;
    
    #[tokio::test]
    async fn test_user_creation() {
        let docker = Cli::default();
        let postgres = docker.run(Postgres::default());
        let connection = setup_test_db(&postgres).await;
        
        let user_repo = UserRepository::new(&connection);
        let user = create_test_user();
        
        let created_user = user_repo.create(user).await.unwrap();
        assert!(created_user.id.is_some());
        assert_eq!(created_user.username, "test@example.com");
    }
    
    #[tokio::test]
    async fn test_credential_storage() {
        let docker = Cli::default();
        let postgres = docker.run(Postgres::default());
        let connection = setup_test_db(&postgres).await;
        
        let cred_repo = CredentialRepository::new(&connection);
        let credential = create_test_credential();
        
        let stored_credential = cred_repo.create(credential).await.unwrap();
        assert!(stored_credential.id.is_some());
        assert!(stored_credential.public_key.len() > 0);
    }
    
    #[tokio::test]
    async fn test_challenge_expiration() {
        let docker = Cli::default();
        let postgres = docker.run(Postgres::default());
        let connection = setup_test_db(&postgres).await;
        
        let challenge_repo = ChallengeRepository::new(&connection);
        let expired_challenge = create_expired_challenge();
        
        challenge_repo.create(expired_challenge).await.unwrap();
        
        let result = challenge_repo.find_valid("expired-challenge-id").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RepositoryError::ChallengeExpired));
    }
}
```

### 2.3 Controller Tests

#### Registration Controller Tests
```rust
#[cfg(test)]
mod registration_controller_tests {
    use super::*;
    use actix_web::{test, web, App};
    use mockall::predicate::*;
    
    #[actix_web::test]
    async fn test_registration_challenge_endpoint() {
        let mut webauthn_service = MockWebAuthnService::new();
        webauthn_service
            .expect_generate_registration_challenge()
            .with(eq("test@example.com"))
            .returning(|_| Ok(create_test_challenge_response()));
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .route("/api/webauthn/registration/challenge", web::post().to(registration_challenge))
        ).await;
        
        let req = test::TestRequest::post()
            .uri("/api/webauthn/registration/challenge")
            .set_json(&RegistrationChallengeRequest {
                username: "test@example.com".to_string(),
                display_name: "Test User".to_string(),
                user_verification: "required".to_string(),
                attestation: "none".to_string(),
            })
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        
        let response: RegistrationChallengeResponse = test::read_body_json(resp).await;
        assert!(response.challenge.len() > 0);
        assert_eq!(response.rp.name, "FIDO Server");
    }
    
    #[actix_web::test]
    async fn test_registration_verification_endpoint() {
        let mut webauthn_service = MockWebAuthnService::new();
        webauthn_service
            .expect_verify_registration()
            .with(always(), always())
            .returning(|_, _| Ok(create_test_verification_response()));
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .route("/api/webauthn/registration/verify", web::post().to(registration_verify))
        ).await;
        
        let req = test::TestRequest::post()
            .uri("/api/webauthn/registration/verify")
            .set_json(&RegistrationVerificationRequest {
                credential: create_test_credential_data(),
                username: "test@example.com".to_string(),
                challenge: "test-challenge".to_string(),
            })
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        
        let response: RegistrationVerificationResponse = test::read_body_json(resp).await;
        assert_eq!(response.status, "ok");
        assert!(response.credential_id.len() > 0);
    }
}
```

## 3. Integration Test Specifications

### 3.1 API Integration Tests

#### Complete Registration Flow Test
```rust
#[cfg(test)]
mod registration_integration_tests {
    use super::*;
    use actix_web::{test, web, App};
    use testcontainers::clients::Cli;
    use testcontainers::images::postgres::Postgres;
    
    #[actix_web::test]
    async fn test_complete_registration_flow() {
        // Setup test database
        let docker = Cli::default();
        let postgres = docker.run(Postgres::default());
        let db_pool = setup_test_db_pool(&postgres).await;
        
        // Setup application with test dependencies
        let app_data = setup_test_app_data(db_pool).await;
        
        let app = test::init_service(
            App::new()
                .app_data(app_data)
                .configure(configure_routes)
        ).await;
        
        // Step 1: Request registration challenge
        let challenge_req = test::TestRequest::post()
            .uri("/api/webauthn/registration/challenge")
            .set_json(&RegistrationChallengeRequest {
                username: "integration@example.com".to_string(),
                display_name: "Integration Test User".to_string(),
                user_verification: "required".to_string(),
                attestation: "none".to_string(),
            })
            .to_request();
        
        let challenge_resp = test::call_service(&app, challenge_req).await;
        assert!(challenge_resp.status().is_success());
        
        let challenge_response: RegistrationChallengeResponse = 
            test::read_body_json(challenge_resp).await;
        
        // Step 2: Simulate credential creation and verification
        let credential_data = simulate_credential_creation(&challenge_response).await;
        
        // Step 3: Verify registration
        let verify_req = test::TestRequest::post()
            .uri("/api/webauthn/registration/verify")
            .set_json(&RegistrationVerificationRequest {
                credential: credential_data,
                username: "integration@example.com".to_string(),
                challenge: challenge_response.challenge,
            })
            .to_request();
        
        let verify_resp = test::call_service(&app, verify_req).await;
        assert!(verify_resp.status().is_success());
        
        let verify_response: RegistrationVerificationResponse = 
            test::read_body_json(verify_resp).await;
        assert_eq!(verify_response.status, "ok");
        
        // Verify credential was stored in database
        let stored_credential = verify_credential_in_db(
            &db_pool, 
            &verify_response.credential_id
        ).await;
        assert!(stored_credential.is_some());
    }
}
```

#### Complete Authentication Flow Test
```rust
#[actix_web::test]
async fn test_complete_authentication_flow() {
    // Setup test environment
    let (app, db_pool) = setup_test_environment().await;
    
    // Step 1: Register a user and credential
    let (username, credential_id) = register_test_user(&app).await;
    
    // Step 2: Request authentication challenge
    let auth_challenge_req = test::TestRequest::post()
        .uri("/api/webauthn/authentication/challenge")
        .set_json(&AuthenticationChallengeRequest {
            username: username.clone(),
            user_verification: "required".to_string(),
        })
        .to_request();
    
    let auth_challenge_resp = test::call_service(&app, auth_challenge_req).await;
    assert!(auth_challenge_resp.status().is_success());
    
    let auth_challenge_response: AuthenticationChallengeResponse = 
        test::read_body_json(auth_challenge_resp).await;
    
    // Step 3: Simulate authentication assertion
    let assertion_data = simulate_authentication_assertion(
        &auth_challenge_response, 
        &credential_id
    ).await;
    
    // Step 4: Verify authentication
    let auth_verify_req = test::TestRequest::post()
        .uri("/api/webauthn/authentication/verify")
        .set_json(&AuthenticationVerificationRequest {
            credential: assertion_data,
            username: username.clone(),
            challenge: auth_challenge_response.challenge,
        })
        .to_request();
    
    let auth_verify_resp = test::call_service(&app, auth_verify_req).await;
    assert!(auth_verify_resp.status().is_success());
    
    let auth_verify_response: AuthenticationVerificationResponse = 
        test::read_body_json(auth_verify_resp).await;
    assert_eq!(auth_verify_response.status, "ok");
    assert!(auth_verify_response.session_token.len() > 0);
    
    // Verify session was created
    let session = verify_session_in_db(&db_pool, &auth_verify_response.session_token).await;
    assert!(session.is_some());
    assert_eq!(session.unwrap().username, username);
}
```

### 3.2 Database Integration Tests

#### Transaction and Concurrency Tests
```rust
#[tokio::test]
async fn test_concurrent_credential_creation() {
    let db_pool = setup_test_db_pool().await;
    
    let user_id = create_test_user(&db_pool).await;
    
    // Spawn multiple concurrent credential creation tasks
    let mut handles = vec![];
    for i in 0..10 {
        let pool = db_pool.clone();
        let uid = user_id;
        let handle = tokio::spawn(async move {
            let credential = create_test_credential_with_id(i);
            let repo = CredentialRepository::new(&pool);
            repo.create(credential).await
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // Verify all credentials were created successfully
    for result in results {
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
    
    // Verify all credentials exist in database
    let repo = CredentialRepository::new(&db_pool);
    let credentials = repo.find_by_user_id(user_id).await.unwrap();
    assert_eq!(credentials.len(), 10);
}

#[tokio::test]
async fn test_challenge_expiration_cleanup() {
    let db_pool = setup_test_db_pool().await;
    
    // Create expired challenges
    let challenge_repo = ChallengeRepository::new(&db_pool);
    for i in 0..5 {
        let expired_challenge = create_expired_challenge_with_id(i);
        challenge_repo.create(expired_challenge).await.unwrap();
    }
    
    // Run cleanup task
    cleanup_expired_challenges(&db_pool).await;
    
    // Verify expired challenges were removed
    let active_challenges = challenge_repo.find_all_active().await.unwrap();
    assert_eq!(active_challenges.len(), 0);
}
```

## 4. Security Test Specifications

### 4.1 FIDO2 Compliance Security Tests

#### Challenge Replay Protection Tests
```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_challenge_replay_attack_prevention() {
        let (app, _) = setup_test_environment().await;
        
        // Step 1: Get registration challenge
        let challenge_req = test::TestRequest::post()
            .uri("/api/webauthn/registration/challenge")
            .set_json(&RegistrationChallengeRequest {
                username: "security@example.com".to_string(),
                display_name: "Security Test".to_string(),
                user_verification: "required".to_string(),
                attestation: "none".to_string(),
            })
            .to_request();
        
        let challenge_resp = test::call_service(&app, challenge_req).await;
        let challenge_response: RegistrationChallengeResponse = 
            test::read_body_json(challenge_resp).await;
        
        // Step 2: Create valid credential
        let credential_data = simulate_credential_creation(&challenge_response).await;
        
        // Step 3: Verify registration (first use - should succeed)
        let verify_req = test::TestRequest::post()
            .uri("/api/webauthn/registration/verify")
            .set_json(&RegistrationVerificationRequest {
                credential: credential_data.clone(),
                username: "security@example.com".to_string(),
                challenge: challenge_response.challenge.clone(),
            })
            .to_request();
        
        let verify_resp = test::call_service(&app, verify_req).await;
        assert!(verify_resp.status().is_success());
        
        // Step 4: Try to reuse same challenge (should fail)
        let replay_req = test::TestRequest::post()
            .uri("/api/webauthn/registration/verify")
            .set_json(&RegistrationVerificationRequest {
                credential: credential_data,
                username: "security@example.com".to_string(),
                challenge: challenge_response.challenge,
            })
            .to_request();
        
        let replay_resp = test::call_service(&app, replay_req).await;
        assert!(replay_resp.status().is_client_error());
        
        let error_response: ErrorResponse = test::read_body_json(replay_resp).await;
        assert_eq!(error_response.error.code, "CHALLENGE_ALREADY_USED");
    }
    
    #[actix_web::test]
    async fn test_rp_id_validation() {
        let (app, _) = setup_test_environment().await;
        
        // Create challenge with invalid RP ID
        let mut challenge_response = create_test_challenge_response();
        challenge_response.rp.id = "malicious.com".to_string();
        
        let credential_data = simulate_credential_creation(&challenge_response).await;
        
        let verify_req = test::TestRequest::post()
            .uri("/api/webauthn/registration/verify")
            .set_json(&RegistrationVerificationRequest {
                credential: credential_data,
                username: "security@example.com".to_string(),
                challenge: challenge_response.challenge,
            })
            .to_request();
        
        let verify_resp = test::call_service(&app, verify_req).await;
        assert!(verify_resp.status().is_client_error());
        
        let error_response: ErrorResponse = test::read_body_json(verify_resp).await;
        assert_eq!(error_response.error.code, "INVALID_RP_ID");
    }
    
    #[actix_web::test]
    async fn test_user_verification_bypass_prevention() {
        let (app, _) = setup_test_environment().await;
        
        // Register user with UV required
        let (username, credential_id) = register_test_user_with_uv_required(&app).await;
        
        // Create authentication challenge
        let auth_challenge_req = test::TestRequest::post()
            .uri("/api/webauthn/authentication/challenge")
            .set_json(&AuthenticationChallengeRequest {
                username: username.clone(),
                user_verification: "required".to_string(),
            })
            .to_request();
        
        let auth_challenge_resp = test::call_service(&app, auth_challenge_req).await;
        let auth_challenge_response: AuthenticationChallengeResponse = 
            test::read_body_json(auth_challenge_resp).await;
        
        // Create assertion without user verification
        let assertion_data = simulate_authentication_assertion_without_uv(
            &auth_challenge_response, 
            &credential_id
        ).await;
        
        let auth_verify_req = test::TestRequest::post()
            .uri("/api/webauthn/authentication/verify")
            .set_json(&AuthenticationVerificationRequest {
                credential: assertion_data,
                username: username.clone(),
                challenge: auth_challenge_response.challenge,
            })
            .to_request();
        
        let auth_verify_resp = test::call_service(&app, auth_verify_req).await;
        assert!(auth_verify_resp.status().is_client_error());
        
        let error_response: ErrorResponse = test::read_body_json(auth_verify_resp).await;
        assert_eq!(error_response.error.code, "USER_VERIFICATION_REQUIRED");
    }
}
```

### 4.2 Input Validation Security Tests

#### SQL Injection Prevention Tests
```rust
#[actix_web::test]
async fn test_sql_injection_prevention() {
    let (app, _) = setup_test_environment().await;
    
    // Attempt SQL injection through username
    let malicious_username = "'; DROP TABLE users; --";
    
    let challenge_req = test::TestRequest::post()
        .uri("/api/webauthn/registration/challenge")
        .set_json(&RegistrationChallengeRequest {
            username: malicious_username.to_string(),
            display_name: "Malicious User".to_string(),
            user_verification: "required".to_string(),
            attestation: "none".to_string(),
        })
        .to_request();
    
    let challenge_resp = test::call_service(&app, challenge_req).await;
    
    // Should either succeed with sanitized input or fail gracefully
    // But should not cause database corruption
    assert!(challenge_resp.status().is_success() || challenge_resp.status().is_client_error());
    
    // Verify users table still exists and is intact
    let db_pool = get_test_db_pool();
    let result = sqlx::query("SELECT COUNT(*) FROM users")
        .fetch_one(&db_pool)
        .await;
    assert!(result.is_ok());
}

#[actix_web::test]
async fn test_xss_prevention() {
    let (app, _) = setup_test_environment().await;
    
    // Attempt XSS through display name
    let xss_payload = "<script>alert('xss')</script>";
    
    let challenge_req = test::TestRequest::post()
        .uri("/api/webauthn/registration/challenge")
        .set_json(&RegistrationChallengeRequest {
            username: "xss@example.com".to_string(),
            display_name: xss_payload.to_string(),
            user_verification: "required".to_string(),
            attestation: "none".to_string(),
        })
        .to_request();
    
    let challenge_resp = test::call_service(&app, challenge_req).await;
    assert!(challenge_resp.status().is_success());
    
    let challenge_response: RegistrationChallengeResponse = 
        test::read_body_json(challenge_resp).await;
    
    // Verify XSS payload is escaped or sanitized
    assert!(!challenge_response.user.display_name.contains("<script>"));
}
```

### 4.3 Rate Limiting Tests

#### Brute Force Prevention Tests
```rust
#[actix_web::test]
async fn test_authentication_rate_limiting() {
    let (app, _) = setup_test_environment().await;
    
    // Register a test user
    let (username, _) = register_test_user(&app).await;
    
    // Attempt multiple failed authentications
    for i in 0..10 {
        let auth_challenge_req = test::TestRequest::post()
            .uri("/api/webauthn/authentication/challenge")
            .set_json(&AuthenticationChallengeRequest {
                username: username.clone(),
                user_verification: "required".to_string(),
            })
            .to_request();
        
        let auth_challenge_resp = test::call_service(&app, auth_challenge_req).await;
        assert!(auth_challenge_resp.status().is_success());
        
        let auth_challenge_response: AuthenticationChallengeResponse = 
            test::read_body_json(auth_challenge_resp).await;
        
        // Create invalid assertion
        let invalid_assertion = create_invalid_assertion();
        
        let auth_verify_req = test::TestRequest::post()
            .uri("/api/webauthn/authentication/verify")
            .set_json(&AuthenticationVerificationRequest {
                credential: invalid_assertion,
                username: username.clone(),
                challenge: auth_challenge_response.challenge,
            })
            .to_request();
        
        let auth_verify_resp = test::call_service(&app, auth_verify_req).await;
        
        // After several attempts, should be rate limited
        if i >= 5 {
            assert_eq!(auth_verify_resp.status(), actix_web::http::StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
```

## 5. Performance Test Specifications

### 5.1 Load Testing

#### Concurrent User Load Test
```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::{Duration, Instant};
    
    #[tokio::test]
    async fn test_concurrent_registration_load() {
        let (app, _) = setup_test_environment().await;
        
        let start_time = Instant::now();
        let concurrent_users = 100;
        
        let mut handles = vec![];
        for i in 0..concurrent_users {
            let app_clone = app.clone();
            let handle = tokio::spawn(async move {
                let username = format!("loadtest{}@example.com", i);
                let display_name = format!("Load Test User {}", i);
                
                // Registration challenge
                let challenge_req = test::TestRequest::post()
                    .uri("/api/webauthn/registration/challenge")
                    .set_json(&RegistrationChallengeRequest {
                        username: username.clone(),
                        display_name,
                        user_verification: "required".to_string(),
                        attestation: "none".to_string(),
                    })
                    .to_request();
                
                let challenge_resp = test::call_service(&app_clone, challenge_req).await;
                assert!(challenge_resp.status().is_success());
                
                let challenge_response: RegistrationChallengeResponse = 
                    test::read_body_json(challenge_resp).await;
                
                // Simulate credential creation and verification
                let credential_data = simulate_credential_creation(&challenge_response).await;
                
                let verify_req = test::TestRequest::post()
                    .uri("/api/webauthn/registration/verify")
                    .set_json(&RegistrationVerificationRequest {
                        credential: credential_data,
                        username,
                        challenge: challenge_response.challenge,
                    })
                    .to_request();
                
                let verify_resp = test::call_service(&app_clone, verify_req).await;
                assert!(verify_resp.status().is_success());
                
                true
            });
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        let results: Vec<_> = futures::future::join_all(handles).await;
        let successful_registrations = results.iter().filter(|r| {
            r.as_ref().map(|success| *success).unwrap_or(false)
        }).count();
        
        let elapsed = start_time.elapsed();
        
        // Performance assertions
        assert_eq!(successful_registrations, concurrent_users);
        assert!(elapsed < Duration::from_secs(30)); // Should complete within 30 seconds
        
        let avg_time_per_registration = elapsed / concurrent_users;
        assert!(avg_time_per_registration < Duration::from_millis(300)); // < 300ms per registration
    }
    
    #[tokio::test]
    async fn test_authentication_performance() {
        let (app, _) = setup_test_environment().await;
        
        // Register test users
        let mut users = vec![];
        for i in 0..50 {
            let (username, credential_id) = register_test_user_with_id(&app, i).await;
            users.push((username, credential_id));
        }
        
        let start_time = Instant::now();
        
        // Concurrent authentication attempts
        let mut handles = vec![];
        for (username, credential_id) in users {
            let app_clone = app.clone();
            let handle = tokio::spawn(async move {
                // Authentication challenge
                let auth_challenge_req = test::TestRequest::post()
                    .uri("/api/webauthn/authentication/challenge")
                    .set_json(&AuthenticationChallengeRequest {
                        username: username.clone(),
                        user_verification: "required".to_string(),
                    })
                    .to_request();
                
                let auth_challenge_resp = test::call_service(&app_clone, auth_challenge_req).await;
                assert!(auth_challenge_resp.status().is_success());
                
                let auth_challenge_response: AuthenticationChallengeResponse = 
                    test::read_body_json(auth_challenge_resp).await;
                
                // Create assertion and verify
                let assertion_data = simulate_authentication_assertion(
                    &auth_challenge_response, 
                    &credential_id
                ).await;
                
                let auth_verify_req = test::TestRequest::post()
                    .uri("/api/webauthn/authentication/verify")
                    .set_json(&AuthenticationVerificationRequest {
                        credential: assertion_data,
                        username,
                        challenge: auth_challenge_response.challenge,
                    })
                    .to_request();
                
                let auth_verify_resp = test::call_service(&app_clone, auth_verify_req).await;
                assert!(auth_verify_resp.status().is_success());
                
                true
            });
            handles.push(handle);
        }
        
        let results: Vec<_> = futures::future::join_all(handles).await;
        let successful_authentications = results.iter().filter(|r| {
            r.as_ref().map(|success| *success).unwrap_or(false)
        }).count();
        
        let elapsed = start_time.elapsed();
        
        assert_eq!(successful_authentications, 50);
        assert!(elapsed < Duration::from_secs(15)); // Should complete within 15 seconds
        
        let avg_time_per_auth = elapsed / 50;
        assert!(avg_time_per_auth < Duration::from_millis(300)); // < 300ms per authentication
    }
}
```

## 6. Compliance Test Specifications

### 6.1 FIDO2 Specification Compliance Tests

#### WebAuthn API Compliance Tests
```rust
#[cfg(test)]
mod compliance_tests {
    use super::*;
    
    #[test]
    fn test_client_data_json_structure_compliance() {
        // Test that client data JSON follows WebAuthn specification
        let client_data = create_test_client_data();
        
        // Required fields according to WebAuthn §5.8.1
        assert!(client_data.contains("\"type\""));
        assert!(client_data.contains("\"challenge\""));
        assert!(client_data.contains("\"origin\""));
        assert!(client_data.contains("\"crossOrigin\""));
        
        // Parse and validate structure
        let parsed: serde_json::Value = serde_json::from_str(&client_data).unwrap();
        assert!(parsed.get("type").is_some());
        assert!(parsed.get("challenge").is_some());
        assert!(parsed.get("origin").is_some());
        assert!(parsed.get("crossOrigin").is_some());
    }
    
    #[test]
    fn test_attestation_object_compliance() {
        // Test attestation object structure compliance
        let attestation_obj = create_test_attestation_object();
        
        // Parse CBOR and validate structure
        let parsed: cbor::Value = cbor::from_slice(&attestation_obj).unwrap();
        
        // Required fields according to WebAuthn §5.3.1
        assert!(parsed.get("fmt").is_some());
        assert!(parsed.get("attStmt").is_some());
        assert!(parsed.get("authData").is_some());
        
        // Validate authData structure
        let auth_data = parsed.get("authData").unwrap().as_bytes().unwrap();
        assert!(auth_data.len() >= 37); // Minimum authData length
        
        // Validate RP ID hash (32 bytes)
        let rp_id_hash = &auth_data[0..32];
        assert_eq!(rp_id_hash.len(), 32);
        
        // Validate flags (1 byte)
        let flags = auth_data[32];
        assert!(flags & 0x01 != 0); // User Present flag should be set
        
        // Validate sign counter (4 bytes)
        let sign_counter = &auth_data[33..37];
        assert_eq!(sign_counter.len(), 4);
    }
    
    #[test]
    fn test_authenticator_data_compliance() {
        // Test authenticator data structure compliance
        let auth_data = create_test_authenticator_data();
        
        assert!(auth_data.len() >= 37);
        
        // RP ID hash
        let rp_id_hash = &auth_data[0..32];
        assert_eq!(rp_id_hash.len(), 32);
        
        // Flags
        let flags = auth_data[32];
        
        // Test flag bits
        let user_present = (flags & 0x01) != 0;
        let user_verified = (flags & 0x04) != 0;
        let attested_credential_data = (flags & 0x40) != 0;
        let extension_data = (flags & 0x80) != 0;
        
        // Sign counter
        let sign_counter = u32::from_be_bytes([
            auth_data[33], auth_data[34], auth_data[35], auth_data[36]
        ]);
        
        // Validate sign counter is reasonable
        assert!(sign_counter <= 0xFFFFFFFF);
        
        // If attested credential data is present, validate its structure
        if attested_credential_data {
            let remaining_data = &auth_data[37..];
            assert!(remaining_data.len() >= 18); // Minimum AAGUID + credential ID length
            
            // AAGUID (16 bytes)
            let aaguid = &remaining_data[0..16];
            assert_eq!(aaguid.len(), 16);
            
            // Credential ID length (2 bytes)
            let cred_id_len = u16::from_be_bytes([
                remaining_data[16], remaining_data[17]
            ]);
            
            // Credential ID
            let cred_id = &remaining_data[18..18 + cred_id_len as usize];
            assert_eq!(cred_id.len(), cred_id_len as usize);
            
            // Public key (remaining data)
            let public_key = &remaining_data[18 + cred_id_len as usize..];
            assert!(!public_key.is_empty());
        }
    }
}
```

### 6.2 Algorithm Compliance Tests

#### Cryptographic Algorithm Tests
```rust
#[test]
fn test_es256_algorithm_compliance() {
    // Test ES256 (ECDSA with P-256 and SHA-256) compliance
    let key_pair = generate_es256_key_pair();
    let message = b"test message";
    let signature = sign_es256(&key_pair, message);
    
    // Verify signature
    let verification_result = verify_es256(&key_pair.public_key, message, &signature);
    assert!(verification_result);
    
    // Test with wrong message (should fail)
    let wrong_message = b"wrong message";
    let wrong_verification = verify_es256(&key_pair.public_key, wrong_message, &signature);
    assert!(!wrong_verification);
}

#[test]
fn test_rs256_algorithm_compliance() {
    // Test RS256 (RSASSA-PKCS1-v1_5 with SHA-256) compliance
    let key_pair = generate_rs256_key_pair();
    let message = b"test message";
    let signature = sign_rs256(&key_pair, message);
    
    // Verify signature
    let verification_result = verify_rs256(&key_pair.public_key, message, &signature);
    assert!(verification_result);
    
    // Test with wrong message (should fail)
    let wrong_message = b"wrong message";
    let wrong_verification = verify_rs256(&key_pair.public_key, wrong_message, &signature);
    assert!(!wrong_verification);
}

#[test]
fn test_eddsa_algorithm_compliance() {
    // Test EdDSA compliance
    let key_pair = generate_eddsa_key_pair();
    let message = b"test message";
    let signature = sign_eddsa(&key_pair, message);
    
    // Verify signature
    let verification_result = verify_eddsa(&key_pair.public_key, message, &signature);
    assert!(verification_result);
    
    // Test with wrong message (should fail)
    let wrong_message = b"wrong message";
    let wrong_verification = verify_eddsa(&key_pair.public_key, wrong_message, &signature);
    assert!(!wrong_verification);
}
```

## 7. Test Execution and Reporting

### 7.1 Test Categories Execution

#### Unit Test Execution
```bash
# Run all unit tests
cargo test --lib

# Run specific module tests
cargo test webauthn::service::tests

# Run with coverage
cargo tarpaulin --out Html --output-dir coverage/
```

#### Integration Test Execution
```bash
# Run all integration tests
cargo test --test integration

# Run specific integration test
cargo test --test integration registration_flow

# Run with database
cargo test --test integration --features test-db
```

#### Security Test Execution
```bash
# Run security tests
cargo test --test security

# Run compliance tests
cargo test --test compliance

# Run performance tests
cargo test --test performance -- --ignored
```

### 7.2 Continuous Integration Testing

#### GitHub Actions Configuration
```yaml
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
    
    - name: Check formatting
      run: cargo fmt -- --check
    
    - name: Run clippy
      run: cargo clippy -- -D warnings
    
    - name: Run unit tests
      run: cargo test --lib
    
    - name: Run integration tests
      run: cargo test --test integration
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost/postgres
    
    - name: Run security tests
      run: cargo test --test security
    
    - name: Run compliance tests
      run: cargo test --test compliance
    
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml --output-dir coverage/
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: coverage/cobertura.xml
```

### 7.3 Test Reporting

#### Coverage Requirements
- Unit test coverage: ≥95%
- Integration test coverage: ≥90%
- Security test coverage: 100%
- Compliance test coverage: 100%

#### Quality Gates
- All tests must pass
- No critical security vulnerabilities
- Code coverage thresholds met
- Performance benchmarks met
- Compliance tests pass

This comprehensive test plan ensures thorough validation of the FIDO2/WebAuthn server implementation with focus on security, compliance, and reliability.