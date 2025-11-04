# FIDO2/WebAuthn Server Test Specification

## Overview

This document provides a comprehensive testing specification for the FIDO2/WebAuthn Relying Party Server, covering unit tests, integration tests, security tests, and compliance tests to ensure FIDO Alliance specification compliance.

## 1. Testing Strategy

### 1.1 Test Pyramid

```
    E2E Tests (5%)
   ┌─────────────────┐
  │  Integration     │ (25%)
 ┌─────────────────────┐
│    Unit Tests        │ (70%)
└─────────────────────┘
```

### 1.2 Test Categories

| Category | Coverage Target | Tools | Environment |
|----------|----------------|-------|-------------|
| Unit Tests | 95%+ | cargo test, mockall | Local |
| Integration Tests | 100% | actix-test, testcontainers | Docker |
| Security Tests | 100% | custom security framework | Isolated |
| Compliance Tests | 100% | FIDO conformance tools | Staging |
| Performance Tests | 100% | k6, wrk | Load testing |

## 2. Unit Test Specifications

### 2.1 WebAuthn Core Tests

```rust
#[cfg(test)]
mod webauthn_core_tests {
    use super::*;
    use webauthn_rs::prelude::*;
    
    // Test: Challenge Generation
    #[test]
    fn test_challenge_generation() {
        let webauthn = create_webauthn_instance();
        
        // Generate multiple challenges
        let challenges: Vec<String> = (0..1000)
            .map(|_| webauthn.generate_challenge().unwrap())
            .collect();
        
        // Verify uniqueness
        let unique_challenges: HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), challenges.len());
        
        // Verify length (minimum 16 bytes when base64url encoded)
        for challenge in &challenges {
            assert!(challenge.len() >= 16);
        }
        
        // Verify randomness quality (basic statistical test)
        let bytes: Vec<u8> = challenges
            .iter()
            .flat_map(|c| base64::decode_config(c, base64::URL_SAFE_NO_PAD).unwrap())
            .collect();
        
        // Chi-square test for randomness
        let mut counts = [0; 256];
        for byte in &bytes {
            counts[*byte as usize] += 1;
        }
        
        let expected = bytes.len() as f64 / 256.0;
        let chi_square: f64 = counts
            .iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                diff * diff / expected
            })
            .sum();
        
        // Chi-square critical value for 255 degrees of freedom at 0.05 significance
        assert!(chi_square < 293.24);
    }
    
    // Test: RP ID Validation
    #[test]
    fn test_rp_id_validation() {
        let valid_cases = vec![
            "example.com",
            "sub.example.com",
            "localhost",
            "127.0.0.1",
        ];
        
        let invalid_cases = vec![
            "",
            ".example.com",
            "example..com",
            "example.com/",
            "https://example.com",
            "example.com:8080",
        ];
        
        for rp_id in valid_cases {
            assert!(validate_rp_id(rp_id).is_ok(), "Valid RP ID failed: {}", rp_id);
        }
        
        for rp_id in invalid_cases {
            assert!(validate_rp_id(rp_id).is_err(), "Invalid RP ID passed: {}", rp_id);
        }
    }
    
    // Test: Origin Validation
    #[test]
    fn test_origin_validation() {
        let rp_id = "example.com";
        
        let valid_origins = vec![
            "https://example.com",
            "https://example.com:443",
            "https://sub.example.com",
            "https://sub.example.com:8443",
        ];
        
        let invalid_origins = vec![
            "http://example.com",
            "https://evil.com",
            "https://example.org",
            "ftp://example.com",
            "example.com",
        ];
        
        for origin in valid_origins {
            assert!(validate_origin(origin, rp_id).is_ok(), 
                   "Valid origin failed: {} for RP ID: {}", origin, rp_id);
        }
        
        for origin in invalid_origins {
            assert!(validate_origin(origin, rp_id).is_err(), 
                   "Invalid origin passed: {} for RP ID: {}", origin, rp_id);
        }
    }
    
    // Test: Attestation Format Validation
    #[test]
    fn test_attestation_format_validation() {
        let valid_formats = vec!["packed", "fido-u2f", "none", "android-key", "android-safetynet"];
        let invalid_formats = vec!["invalid", "packed-invalid", "", "NONE"];
        
        for format in valid_formats {
            assert!(validate_attestation_format(format).is_ok());
        }
        
        for format in invalid_formats {
            assert!(validate_attestation_format(format).is_err());
        }
    }
    
    // Test: Credential ID Validation
    #[test]
    fn test_credential_id_validation() {
        // Valid credential IDs (base64url encoded)
        let valid_ids = vec![
            "lTqW8uwE5c1iQJj4yJ9QKQ",
            "mYhP3A7vB2nL9xR4wK8sF5g",
            "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        ];
        
        // Invalid credential IDs
        let invalid_ids = vec![
            "", // Empty
            "invalid+base64", // Contains invalid character
            "invalid/base64", // Contains invalid character
            "lTqW8uwE5c1iQJj4yJ9QKQ=", // Contains padding
        ];
        
        for id in valid_ids {
            assert!(validate_credential_id(id).is_ok());
        }
        
        for id in invalid_ids {
            assert!(validate_credential_id(id).is_err());
        }
    }
}
```

### 2.2 Service Layer Tests

```rust
#[cfg(test)]
mod service_tests {
    use super::*;
    use mockall::predicate::*;
    
    // Test: User Service
    #[tokio::test]
    async fn test_user_service_create_user() {
        let mut mock_repo = MockUserRepository::new();
        let user_service = UserService::new(mock_repo.clone());
        
        let user_data = CreateUserRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
        };
        
        // Expect successful creation
        mock_repo
            .expect_create_user()
            .with(eq(user_data.username.clone()), eq(user_data.display_name.clone()))
            .times(1)
            .returning(|_, _| Ok(User::new("test@example.com", "Test User")));
        
        let result = user_service.create_user(user_data).await;
        assert!(result.is_ok());
    }
    
    // Test: Credential Service
    #[tokio::test]
    async fn test_credential_service_store_credential() {
        let mut mock_repo = MockCredentialRepository::new();
        let credential_service = CredentialService::new(mock_repo.clone());
        
        let credential = create_test_credential();
        
        // Expect successful storage
        mock_repo
            .expect_store_credential()
            .with(always(), always())
            .times(1)
            .returning(|_, _| Ok(()));
        
        let result = credential_service.store_credential(credential).await;
        assert!(result.is_ok());
    }
    
    // Test: Challenge Service
    #[tokio::test]
    async fn test_challenge_service_lifecycle() {
        let challenge_service = ChallengeService::new();
        
        // Create challenge
        let challenge = challenge_service
            .create_challenge("user123", ChallengeType::Registration)
            .await
            .unwrap();
        
        // Verify challenge exists
        let exists = challenge_service
            .verify_challenge(&challenge, ChallengeType::Registration)
            .await;
        assert!(exists.is_ok());
        
        // Mark challenge as used
        challenge_service
            .mark_challenge_used(&challenge)
            .await
            .unwrap();
        
        // Verify challenge is now invalid
        let result = challenge_service
            .verify_challenge(&challenge, ChallengeType::Registration)
            .await;
        assert!(matches!(result, Err(WebAuthnError::ChallengeAlreadyUsed)));
    }
}
```

### 2.3 Database Model Tests

```rust
#[cfg(test)]
mod model_tests {
    use super::*;
    
    // Test: User Model
    #[test]
    fn test_user_model_validation() {
        // Valid user
        let valid_user = User::new("test@example.com", "Test User");
        assert!(valid_user.validate().is_ok());
        
        // Invalid email
        let invalid_user = User::new("invalid-email", "Test User");
        assert!(invalid_user.validate().is_err());
        
        // Empty display name
        let invalid_user = User::new("test@example.com", "");
        assert!(invalid_user.validate().is_err());
    }
    
    // Test: Credential Model
    #[test]
    fn test_credential_model_validation() {
        let user_id = Uuid::new_v4();
        let credential_id = "test-credential-id";
        let public_key = vec![1, 2, 3, 4];
        
        // Valid credential
        let valid_credential = Credential::new(
            user_id,
            credential_id,
            public_key.clone(),
            AttestationType::None,
        );
        assert!(valid_credential.validate().is_ok());
        
        // Empty credential ID
        let invalid_credential = Credential::new(
            user_id,
            "",
            public_key,
            AttestationType::None,
        );
        assert!(invalid_credential.validate().is_err());
        
        // Empty public key
        let invalid_credential = Credential::new(
            user_id,
            credential_id,
            vec![],
            AttestationType::None,
        );
        assert!(invalid_credential.validate().is_err());
    }
}
```

## 3. Integration Test Specifications

### 3.1 API Endpoint Tests

```rust
#[cfg(test)]
mod integration_tests {
    use actix_web::{test, App};
    use serde_json::json;
    
    // Test: Registration Begin Endpoint
    #[tokio::test]
    async fn test_registration_begin_success() {
        let app = test::init_service(create_test_app()).await;
        
        let req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(json!({
                "username": "test@example.com",
                "displayName": "Test User",
                "attestation": "none",
                "authenticatorSelection": {
                    "userVerification": "required"
                }
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        
        let response_body: serde_json::Value = test::read_body_json(resp).await;
        
        // Verify response structure
        assert!(response_body.get("challenge").is_some());
        assert!(response_body.get("rp").is_some());
        assert!(response_body.get("user").is_some());
        assert!(response_body.get("pubKeyCredParams").is_some());
        
        // Verify challenge format
        let challenge = response_body["challenge"].as_str().unwrap();
        assert!(base64::decode_config(challenge, base64::URL_SAFE_NO_PAD).is_ok());
    }
    
    // Test: Registration Complete Endpoint
    #[tokio::test]
    async fn test_registration_complete_success() {
        let app = test::init_service(create_test_app()).await;
        
        // First, begin registration
        let begin_req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .to_request();
        
        let begin_resp = test::call_service(&app, begin_req).await;
        let begin_response: serde_json::Value = test::read_body_json(begin_resp).await;
        let challenge = begin_response["challenge"].as_str().unwrap();
        
        // Create mock credential
        let credential = create_mock_credential(challenge);
        
        // Complete registration
        let complete_req = test::TestRequest::post()
            .uri("/webauthn/register/complete")
            .set_json(json!({
                "credential": credential,
                "username": "test@example.com",
                "sessionData": {
                    "challenge": challenge,
                    "timestamp": Utc::now().timestamp()
                }
            }))
            .to_request();
        
        let complete_resp = test::call_service(&app, complete_req).await;
        assert!(complete_resp.status().is_success());
        
        let response_body: serde_json::Value = test::read_body_json(complete_resp).await;
        assert_eq!(response_body["status"], "ok");
        assert!(response_body.get("credentialId").is_some());
    }
    
    // Test: Authentication Begin Endpoint
    #[tokio::test]
    async fn test_authentication_begin_success() {
        let app = test::init_service(create_test_app()).await;
        
        // First, register a user and credential
        setup_test_user_with_credential(&app).await;
        
        let req = test::TestRequest::post()
            .uri("/webauthn/authenticate/begin")
            .set_json(json!({
                "username": "test@example.com",
                "userVerification": "required"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        
        let response_body: serde_json::Value = test::read_body_json(resp).await;
        
        // Verify response structure
        assert!(response_body.get("challenge").is_some());
        assert!(response_body.get("allowCredentials").is_some());
        assert_eq!(response_body["userVerification"], "required");
        
        // Verify allowCredentials contains our test credential
        let allow_creds = response_body["allowCredentials"].as_array().unwrap();
        assert!(!allow_creds.is_empty());
    }
    
    // Test: Authentication Complete Endpoint
    #[tokio::test]
    async fn test_authentication_complete_success() {
        let app = test::init_service(create_test_app()).await;
        
        // Setup user and credential
        setup_test_user_with_credential(&app).await;
        
        // Begin authentication
        let begin_req = test::TestRequest::post()
            .uri("/webauthn/authenticate/begin")
            .set_json(json!({
                "username": "test@example.com"
            }))
            .to_request();
        
        let begin_resp = test::call_service(&app, begin_req).await;
        let begin_response: serde_json::Value = test::read_body_json(begin_resp).await;
        let challenge = begin_response["challenge"].as_str().unwrap();
        
        // Create mock assertion
        let assertion = create_mock_assertion(challenge);
        
        // Complete authentication
        let complete_req = test::TestRequest::post()
            .uri("/webauthn/authenticate/complete")
            .set_json(json!({
                "credential": assertion,
                "username": "test@example.com",
                "sessionData": {
                    "challenge": challenge,
                    "timestamp": Utc::now().timestamp()
                }
            }))
            .to_request();
        
        let complete_resp = test::call_service(&app, complete_req).await;
        assert!(complete_resp.status().is_success());
        
        let response_body: serde_json::Value = test::read_body_json(complete_resp).await;
        assert_eq!(response_body["status"], "ok");
        assert!(response_body.get("user").is_some());
    }
}
```

### 3.2 Database Integration Tests

```rust
#[cfg(test)]
mod database_integration_tests {
    use sqlx::PgPool;
    use testcontainers::clients::Cli;
    use testcontainers::images::postgres::Postgres;
    
    // Test: User Repository
    #[tokio::test]
    async fn test_user_repository_crud() {
        let docker = Cli::default();
        let postgres = docker.run(Postgres::default());
        let connection_string = format!(
            "postgres://postgres:postgres@localhost:{}/test",
            postgres.get_host_port_ipv4(5432)
        );
        
        let pool = PgPool::connect(&connection_string).await.unwrap();
        run_migrations(&pool).await.unwrap();
        
        let user_repo = PostgresUserRepository::new(pool);
        
        // Create user
        let user = user_repo
            .create_user("test@example.com", "Test User")
            .await
            .unwrap();
        
        // Read user
        let retrieved_user = user_repo
            .get_user_by_id(user.id)
            .await
            .unwrap();
        assert_eq!(retrieved_user.username, "test@example.com");
        
        // Update user
        user_repo
            .update_user_display_name(user.id, "Updated Name")
            .await
            .unwrap();
        
        let updated_user = user_repo
            .get_user_by_id(user.id)
            .await
            .unwrap();
        assert_eq!(updated_user.display_name, "Updated Name");
        
        // Delete user
        user_repo.delete_user(user.id).await.unwrap();
        
        let deleted_user = user_repo.get_user_by_id(user.id).await;
        assert!(deleted_user.is_err());
    }
    
    // Test: Credential Repository
    #[tokio::test]
    async fn test_credential_repository_crud() {
        let docker = Cli::default();
        let postgres = docker.run(Postgres::default());
        let connection_string = format!(
            "postgres://postgres:postgres@localhost:{}/test",
            postgres.get_host_port_ipv4(5432)
        );
        
        let pool = PgPool::connect(&connection_string).await.unwrap();
        run_migrations(&pool).await.unwrap();
        
        let cred_repo = PostgresCredentialRepository::new(pool);
        let user_id = Uuid::new_v4();
        
        // Create credential
        let credential = create_test_credential_with_user_id(user_id);
        let stored_credential = cred_repo
            .store_credential(&credential)
            .await
            .unwrap();
        
        // Read credential
        let retrieved_credential = cred_repo
            .get_credential_by_id(stored_credential.id)
            .await
            .unwrap();
        assert_eq!(retrieved_credential.user_id, user_id);
        
        // Read credentials by user
        let user_credentials = cred_repo
            .get_credentials_by_user_id(user_id)
            .await
            .unwrap();
        assert_eq!(user_credentials.len(), 1);
        
        // Update credential
        cred_repo
            .update_sign_count(stored_credential.id, 42)
            .await
            .unwrap();
        
        let updated_credential = cred_repo
            .get_credential_by_id(stored_credential.id)
            .await
            .unwrap();
        assert_eq!(updated_credential.sign_count, 42);
        
        // Delete credential
        cred_repo
            .delete_credential(stored_credential.id)
            .await
            .unwrap();
        
        let deleted_credential = cred_repo
            .get_credential_by_id(stored_credential.id)
            .await;
        assert!(deleted_credential.is_err());
    }
}
```

## 4. Security Test Specifications

### 4.1 Replay Attack Tests

```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    // Test: Challenge Replay Prevention
    #[tokio::test]
    async fn test_challenge_replay_prevention() {
        let app = test::init_service(create_test_app()).await;
        
        // Begin registration
        let begin_req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .to_request();
        
        let begin_resp = test::call_service(&app, begin_req).await;
        let begin_response: serde_json::Value = test::read_body_json(begin_resp).await;
        let challenge = begin_response["challenge"].as_str().unwrap();
        
        // Create mock credential
        let credential = create_mock_credential(challenge);
        
        // Complete registration first time
        let complete_req = test::TestRequest::post()
            .uri("/webauthn/register/complete")
            .set_json(json!({
                "credential": credential.clone(),
                "username": "test@example.com",
                "sessionData": {
                    "challenge": challenge,
                    "timestamp": Utc::now().timestamp()
                }
            }))
            .to_request();
        
        let complete_resp = test::call_service(&app, complete_req).await;
        assert!(complete_resp.status().is_success());
        
        // Try to use same challenge again (should fail)
        let replay_req = test::TestRequest::post()
            .uri("/webauthn/register/complete")
            .set_json(json!({
                "credential": credential,
                "username": "test@example.com",
                "sessionData": {
                    "challenge": challenge,
                    "timestamp": Utc::now().timestamp()
                }
            }))
            .to_request();
        
        let replay_resp = test::call_service(&app, replay_req).await;
        assert!(!replay_resp.status().is_success());
        
        let error_response: serde_json::Value = test::read_body_json(replay_resp).await;
        assert!(error_response["errorMessage"].as_str().unwrap().contains("challenge"));
    }
    
    // Test: Authentication Counter Replay Detection
    #[tokio::test]
    async fn test_authentication_counter_replay() {
        let app = test::init_service(create_test_app()).await;
        
        // Setup user and credential
        setup_test_user_with_credential(&app).await;
        
        // Begin authentication
        let begin_req = test::TestRequest::post()
            .uri("/webauthn/authenticate/begin")
            .set_json(json!({
                "username": "test@example.com"
            }))
            .to_request();
        
        let begin_resp = test::call_service(&app, begin_req).await;
        let begin_response: serde_json::Value = test::read_body_json(begin_resp).await;
        let challenge = begin_response["challenge"].as_str().unwrap();
        
        // Create assertion with old counter
        let mut assertion = create_mock_assertion(challenge);
        assertion["response"]["authenticatorData"] = 
            base64::encode(create_authenticator_data_with_counter(0));
        
        // Complete authentication (should fail due to counter replay)
        let complete_req = test::TestRequest::post()
            .uri("/webauthn/authenticate/complete")
            .set_json(json!({
                "credential": assertion,
                "username": "test@example.com",
                "sessionData": {
                    "challenge": challenge,
                    "timestamp": Utc::now().timestamp()
                }
            }))
            .to_request();
        
        let complete_resp = test::call_service(&app, complete_req).await;
        assert!(!complete_resp.status().is_success());
    }
    
    // Test: Origin Validation Attack
    #[tokio::test]
    async fn test_origin_validation_attack() {
        let app = test::init_service(create_test_app()).await;
        
        // Begin registration
        let begin_req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .to_request();
        
        let begin_resp = test::call_service(&app, begin_req).await;
        let begin_response: serde_json::Value = test::read_body_json(begin_resp).await;
        let challenge = begin_response["challenge"].as_str().unwrap();
        
        // Create credential with malicious origin
        let mut credential = create_mock_credential(challenge);
        let mut client_data = create_mock_client_data(challenge);
        client_data["origin"] = json!("https://evil.com");
        credential["response"]["clientDataJSON"] = 
            base64::encode(serde_json::to_vec(&client_data).unwrap());
        
        // Try to complete registration (should fail)
        let complete_req = test::TestRequest::post()
            .uri("/webauthn/register/complete")
            .set_json(json!({
                "credential": credential,
                "username": "test@example.com",
                "sessionData": {
                    "challenge": challenge,
                    "timestamp": Utc::now().timestamp()
                }
            }))
            .to_request();
        
        let complete_resp = test::call_service(&app, complete_req).await;
        assert!(!complete_resp.status().is_success());
    }
    
    // Test: Credential Enumeration Prevention
    #[tokio::test]
    async fn test_credential_enumeration_prevention() {
        let app = test::init_service(create_test_app()).await;
        
        // Try authentication with non-existent user
        let req = test::TestRequest::post()
            .uri("/webauthn/authenticate/begin")
            .set_json(json!({
                "username": "nonexistent@example.com"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return success with empty allowCredentials
        assert!(resp.status().is_success());
        
        let response_body: serde_json::Value = test::read_body_json(resp).await;
        let allow_creds = response_body["allowCredentials"].as_array().unwrap();
        assert_eq!(allow_creds.len(), 0);
        
        // Response should be identical to existing user with no credentials
        // This prevents user enumeration
    }
}
```

### 4.2 Input Validation Tests

```rust
#[cfg(test)]
mod input_validation_tests {
    use super::*;
    
    // Test: Malformed JSON Handling
    #[tokio::test]
    async fn test_malformed_json_handling() {
        let app = test::init_service(create_test_app()).await;
        
        // Send malformed JSON
        let req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_payload("{ invalid json }")
            .insert_header(("content-type", "application/json"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
    
    // Test: Oversized Payload Handling
    #[tokio::test]
    async fn test_oversized_payload_handling() {
        let app = test::init_service(create_test_app()).await;
        
        // Create oversized payload
        let oversized_data = "x".repeat(10 * 1024 * 1024); // 10MB
        let req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(json!({
                "username": oversized_data,
                "displayName": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }
    
    // Test: SQL Injection Prevention
    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let app = test::init_service(create_test_app()).await;
        
        let malicious_inputs = vec![
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "admin' /*",
        ];
        
        for malicious_input in malicious_inputs {
            let req = test::TestRequest::post()
                .uri("/webauthn/register/begin")
                .set_json(json!({
                    "username": malicious_input,
                    "displayName": "Test User"
                }))
                .to_request();
            
            let resp = test::call_service(&app, req).await;
            
            // Should handle gracefully without database errors
            assert!(!resp.status().is_server_error());
        }
    }
    
    // Test: XSS Prevention
    #[tokio::test]
    async fn test_xss_prevention() {
        let app = test::init_service(create_test_app()).await;
        
        let xss_payloads = vec![
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ];
        
        for payload in xss_payloads {
            let req = test::TestRequest::post()
                .uri("/webauthn/register/begin")
                .set_json(json!({
                    "username": "test@example.com",
                    "displayName": payload
                }))
                .to_request();
            
            let resp = test::call_service(&app, req).await;
            assert!(resp.status().is_success());
            
            let response_body: serde_json::Value = test::read_body_json(resp).await;
            let display_name = response_body["user"]["displayName"].as_str().unwrap();
            
            // Should be escaped or sanitized
            assert!(!display_name.contains("<script>"));
            assert!(!display_name.contains("javascript:"));
        }
    }
}
```

## 5. Compliance Test Specifications

### 5.1 FIDO2 Conformance Tests

```rust
#[cfg(test)]
mod fido_conformance_tests {
    use super::*;
    
    // Test: RP ID Conformance
    #[test]
    fn test_rp_id_conformance() {
        // Test cases from FIDO conformance suite
        let test_cases = vec![
            // Valid RP IDs
            ("example.com", true),
            ("sub.example.com", true),
            ("localhost", true),
            ("127.0.0.1", true),
            
            // Invalid RP IDs
            ("", false),
            (".example.com", false),
            ("example..com", false),
            ("example.com/", false),
            ("https://example.com", false),
            ("example.com:8080", false),
        ];
        
        for (rp_id, expected_valid) in test_cases {
            let result = validate_rp_id(rp_id);
            assert_eq!(result.is_ok(), expected_valid, 
                      "RP ID '{}' validation failed", rp_id);
        }
    }
    
    // Test: Challenge Conformance
    #[test]
    fn test_challenge_conformance() {
        let webauthn = create_webauthn_instance();
        
        // Generate challenge and verify conformance
        let challenge = webauthn.generate_challenge().unwrap();
        
        // Must be base64url encoded without padding
        assert!(!challenge.ends_with('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        
        // Must decode to valid bytes
        let decoded = base64::decode_config(&challenge, base64::URL_SAFE_NO_PAD).unwrap();
        
        // Must be at least 16 bytes
        assert!(decoded.len() >= 16);
        
        // Must be random (basic test)
        let challenges: Vec<String> = (0..100)
            .map(|_| webauthn.generate_challenge().unwrap())
            .collect();
        let unique_challenges: HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), challenges.len());
    }
    
    // Test: Attestation Statement Conformance
    #[test]
    fn test_attestation_conformance() {
        // Test Packed attestation format
        let packed_attestation = create_packed_attestation();
        let result = verify_attestation(&packed_attestation);
        assert!(result.is_ok());
        
        // Test FIDO-U2F attestation format
        let u2f_attestation = create_u2f_attestation();
        let result = verify_attestation(&u2f_attestation);
        assert!(result.is_ok());
        
        // Test None attestation format
        let none_attestation = create_none_attestation();
        let result = verify_attestation(&none_attestation);
        assert!(result.is_ok());
        
        // Test invalid attestation
        let invalid_attestation = create_invalid_attestation();
        let result = verify_attestation(&invalid_attestation);
        assert!(result.is_err());
    }
    
    // Test: Client Data JSON Conformance
    #[test]
    fn test_client_data_conformance() {
        let client_data = create_valid_client_data();
        
        // Verify required fields
        assert!(client_data.get("type").is_some());
        assert!(client_data.get("challenge").is_some());
        assert!(client_data.get("origin").is_some());
        assert!(client_data.get("crossOrigin").is_some());
        
        // Verify type field
        assert_eq!(client_data["type"], "webauthn.create" /* or "webauthn.get" */);
        
        // Verify challenge format
        let challenge = client_data["challenge"].as_str().unwrap();
        assert!(base64::decode_config(challenge, base64::URL_SAFE_NO_PAD).is_ok());
        
        // Verify origin format
        let origin = client_data["origin"].as_str().unwrap();
        assert!(origin.starts_with("https://"));
    }
    
    // Test: Authenticator Data Conformance
    #[test]
    fn test_authenticator_data_conformance() {
        let auth_data = create_valid_authenticator_data();
        
        // Verify minimum length (32 bytes for RP ID hash + 1 byte flags + 4 bytes counter)
        assert!(auth_data.len() >= 37);
        
        // Verify RP ID hash (first 32 bytes)
        let rp_id_hash = &auth_data[..32];
        assert_eq!(rp_id_hash.len(), 32);
        
        // Verify flags byte
        let flags = auth_data[32];
        assert!(flags & 0x01 != 0); // User Present flag must be set
        
        // Verify signature counter (next 4 bytes)
        let counter_bytes = &auth_data[33..37];
        let counter = u32::from_be_bytes([
            counter_bytes[0],
            counter_bytes[1],
            counter_bytes[2],
            counter_bytes[3],
        ]);
        assert!(counter > 0); // Counter should be positive
    }
}
```

### 5.2 Metadata Service Integration Tests

```rust
#[cfg(test)]
mod metadata_tests {
    use super::*;
    
    // Test: Metadata Statement Verification
    #[tokio::test]
    async fn test_metadata_statement_verification() {
        let metadata_service = MetadataService::new();
        
        // Test valid metadata statement
        let valid_statement = create_valid_metadata_statement();
        let result = metadata_service.verify_statement(&valid_statement).await;
        assert!(result.is_ok());
        
        // Test invalid metadata statement
        let invalid_statement = create_invalid_metadata_statement();
        let result = metadata_service.verify_statement(&invalid_statement).await;
        assert!(result.is_err());
        
        // Test expired metadata statement
        let expired_statement = create_expired_metadata_statement();
        let result = metadata_service.verify_statement(&expired_statement).await;
        assert!(result.is_err());
    }
    
    // Test: AAGUID Validation
    #[tokio::test]
    async fn test_aaguid_validation() {
        let metadata_service = MetadataService::new();
        
        // Test known AAGUID
        let known_aaguid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = metadata_service.validate_aaguid(&known_aaguid).await;
        assert!(result.is_ok());
        
        // Test unknown AAGUID
        let unknown_aaguid = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = metadata_service.validate_aaguid(&unknown_aaguid).await;
        // Should handle gracefully (may be allowed or rejected based on policy)
    }
}
```

## 6. Performance Test Specifications

### 6.1 Load Testing

```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    
    // Test: Concurrent Registration
    #[tokio::test]
    async fn test_concurrent_registration() {
        let app = test::init_service(create_test_app()).await;
        
        let concurrent_requests = 100;
        let mut handles = Vec::new();
        
        for i in 0..concurrent_requests {
            let app_clone = app.clone();
            let handle = tokio::spawn(async move {
                let req = test::TestRequest::post()
                    .uri("/webauthn/register/begin")
                    .set_json(json!({
                        "username": format!("user{}@example.com", i),
                        "displayName": format!("User {}", i)
                    }))
                    .to_request();
                
                let start = Instant::now();
                let resp = test::call_service(&app_clone, req).await;
                let duration = start.elapsed();
                
                (resp.status(), duration)
            });
            
            handles.push(handle);
        }
        
        let mut success_count = 0;
        let mut total_duration = Duration::ZERO;
        let mut max_duration = Duration::ZERO;
        
        for handle in handles {
            let (status, duration) = handle.await.unwrap();
            if status.is_success() {
                success_count += 1;
            }
            total_duration += duration;
            max_duration = max_duration.max(duration);
        }
        
        // Verify success rate
        assert!(success_count >= concurrent_requests * 95 / 100);
        
        // Verify performance (average < 100ms, max < 500ms)
        let avg_duration = total_duration / concurrent_requests as u32;
        assert!(avg_duration < Duration::from_millis(100));
        assert!(max_duration < Duration::from_millis(500));
    }
    
    // Test: Memory Usage Under Load
    #[tokio::test]
    async fn test_memory_usage_under_load() {
        let app = test::init_service(create_test_app()).await;
        
        let initial_memory = get_memory_usage();
        
        // Generate many challenges
        for i in 0..10000 {
            let req = test::TestRequest::post()
                .uri("/webauthn/register/begin")
                .set_json(json!({
                    "username": format!("user{}@example.com", i),
                    "displayName": format!("User {}", i)
                }))
                .to_request();
            
            let _resp = test::call_service(&app, req).await;
        }
        
        let final_memory = get_memory_usage();
        let memory_increase = final_memory - initial_memory;
        
        // Memory increase should be reasonable (< 100MB)
        assert!(memory_increase < 100 * 1024 * 1024);
    }
}
```

## 7. Test Execution Framework

### 7.1 Test Configuration

```toml
# Cargo.toml test configuration
[dev-dependencies]
# Testing framework
tokio-test = "0.4"
actix-test = "0.1"
mockall = "0.13"

# Test utilities
testcontainers = "0.15"
wiremock = "0.6"
proptest = "1.4"
criterion = "0.5"

# Security testing
reqwest = { version = "0.11", features = ["json"] }
serde_json = "1.0"

[[bench]]
name = "webauthn_benchmarks"
harness = false
```

### 7.2 Test Utilities

```rust
// tests/common/mod.rs
pub mod fixtures;
pub mod helpers;
pub mod mocks;

use fixtures::*;
use helpers::*;
use mocks::*;

pub fn create_test_app() -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >,
> {
    App::new()
        .configure(configure_routes)
        .app_data(web::JsonConfig::default().error_handler(json_error_handler))
}

pub async fn setup_test_user_with_credential(app: &AppService) {
    // Create user
    let create_user_req = test::TestRequest::post()
        .uri("/users")
        .set_json(json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .to_request();
    
    let _resp = test::call_service(app, create_user_req).await;
    
    // Register credential
    let begin_req = test::TestRequest::post()
        .uri("/webauthn/register/begin")
        .set_json(json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .to_request();
    
    let begin_resp = test::call_service(app, begin_req).await;
    let begin_response: serde_json::Value = test::read_body_json(begin_resp).await;
    let challenge = begin_response["challenge"].as_str().unwrap();
    
    let credential = create_mock_credential(challenge);
    
    let complete_req = test::TestRequest::post()
        .uri("/webauthn/register/complete")
        .set_json(json!({
            "credential": credential,
            "username": "test@example.com",
            "sessionData": {
                "challenge": challenge,
                "timestamp": Utc::now().timestamp()
            }
        }))
        .to_request();
    
    let _resp = test::call_service(app, complete_req).await;
}
```

## 8. Test Coverage Requirements

### 8.1 Coverage Targets

| Component | Target Coverage | Measurement Tool |
|-----------|----------------|------------------|
| Core WebAuthn Logic | 95% | tarpaulin |
| API Endpoints | 100% | tarpaulin + manual |
| Database Operations | 95% | tarpaulin |
| Error Handling | 100% | tarpaulin |
| Security Functions | 100% | tarpaulin + manual |
| Input Validation | 100% | tarpaulin + property testing |

### 8.2 Coverage Measurement

```bash
# Run tests with coverage
cargo tarpaulin --out Html --output-dir coverage/

# Generate coverage report
cargo tarpaulin --ignore-tests --out Html --output-dir coverage/

# Check coverage thresholds
cargo tarpaulin --ignore-tests --fail-under 95
```

This comprehensive test specification ensures that the FIDO2/WebAuthn server implementation meets all security requirements, FIDO Alliance compliance standards, and performance expectations while maintaining high code quality through extensive testing coverage.