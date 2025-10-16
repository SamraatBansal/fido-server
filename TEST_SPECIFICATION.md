# FIDO2/WebAuthn Server - Test Specification

## Overview

This document provides a comprehensive test specification for the FIDO2/WebAuthn Relying Party Server, covering unit tests, integration tests, security tests, and compliance tests to ensure 95%+ coverage and FIDO Alliance compliance.

## 1. Unit Test Specification

### 1.1 WebAuthn Service Tests

#### Challenge Generation Tests
```rust
#[cfg(test)]
mod challenge_tests {
    use super::*;
    
    #[test]
    fn test_generate_challenge_length() {
        // Test: Challenge must be at least 16 bytes
        let challenge = generate_challenge();
        assert!(challenge.len() >= 16);
    }
    
    #[test]
    fn test_generate_challenge_uniqueness() {
        // Test: Multiple challenges must be unique
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        assert_ne!(challenge1, challenge2);
    }
    
    #[test]
    fn test_generate_challenge_cryptographic() {
        // Test: Challenge must be cryptographically random
        let challenges: Vec<String> = (0..1000).map(|_| generate_challenge()).collect();
        let unique_challenges: HashSet<_> = challenges.iter().collect();
        assert_eq!(unique_challenges.len(), 1000);
    }
    
    #[test]
    fn test_challenge_expiration() {
        // Test: Challenge expiration logic
        let challenge = StoredChallenge {
            id: "test".to_string(),
            challenge: "challenge".to_string(),
            expires_at: Utc::now() - Duration::minutes(1),
            used: false,
        };
        assert!(challenge.is_expired());
    }
    
    #[test]
    fn test_challenge_usage() {
        // Test: Challenge one-time use enforcement
        let mut challenge = StoredChallenge {
            id: "test".to_string(),
            challenge: "challenge".to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
            used: false,
        };
        assert!(!challenge.is_used());
        challenge.mark_used();
        assert!(challenge.is_used());
    }
}
```

#### Attestation Verification Tests
```rust
#[cfg(test)]
mod attestation_tests {
    use super::*;
    
    #[test]
    fn test_valid_packed_attestation() {
        // Test: Valid packed attestation format
        let attestation = create_valid_packed_attestation();
        let result = verify_attestation(&attestation).await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_invalid_packed_attestation() {
        // Test: Invalid packed attestation signature
        let attestation = create_invalid_packed_attestation();
        let result = verify_attestation(&attestation).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidSignature));
    }
    
    #[test]
    fn test_fido_u2f_attestation() {
        // Test: FIDO U2F attestation format
        let attestation = create_fido_u2f_attestation();
        let result = verify_attestation(&attestation).await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_none_attestation() {
        // Test: None attestation format
        let attestation = create_none_attestation();
        let result = verify_attestation(&attestation).await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_unsupported_attestation_format() {
        // Test: Unsupported attestation format
        let attestation = create_unsupported_attestation();
        let result = verify_attestation(&attestation).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UnsupportedFormat));
    }
    
    #[test]
    fn test_attestation_chain_validation() {
        // Test: X.509 certificate chain validation
        let attestation = create_attestation_with_invalid_chain();
        let result = verify_attestation(&attestation).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidCertificateChain));
    }
}
```

#### Assertion Verification Tests
```rust
#[cfg(test)]
mod assertion_tests {
    use super::*;
    
    #[test]
    fn test_valid_assertion() {
        // Test: Valid assertion verification
        let assertion = create_valid_assertion();
        let credential = get_test_credential();
        let result = verify_assertion(&assertion, &credential).await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_invalid_signature() {
        // Test: Invalid assertion signature
        let assertion = create_assertion_with_invalid_signature();
        let credential = get_test_credential();
        let result = verify_assertion(&assertion, &credential).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidSignature));
    }
    
    #[test]
    fn test_counter_regression() {
        // Test: Counter regression detection
        let assertion = create_assertion_with_lower_counter();
        let credential = get_test_credential();
        let result = verify_assertion(&assertion, &credential).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::CounterRegression));
    }
    
    #[test]
    fn test_user_verification_required() {
        // Test: User verification requirement
        let assertion = create_assertion_without_user_verification();
        let credential = get_test_credential();
        let result = verify_assertion_with_uv(&assertion, &credential, UserVerificationPolicy::Required).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UserVerificationRequired));
    }
    
    #[test]
    fn test_invalid_authenticator_data() {
        // Test: Invalid authenticator data
        let assertion = create_assertion_with_invalid_auth_data();
        let credential = get_test_credential();
        let result = verify_assertion(&assertion, &credential).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidAuthenticatorData));
    }
}
```

### 1.2 Model Tests

#### User Model Tests
```rust
#[cfg(test)]
mod user_model_tests {
    use super::*;
    
    #[test]
    fn test_user_creation() {
        // Test: Valid user creation
        let user = User::new("test@example.com", "Test User");
        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(user.is_active);
        assert!(!user.email_verified);
    }
    
    #[test]
    fn test_user_validation() {
        // Test: Username validation
        assert!(User::validate_username("valid@example.com").is_ok());
        assert!(User::validate_username("").is_err());
        assert!(User::validate_username("a".repeat(256).as_str()).is_err());
        assert!(User::validate_username("invalid-email").is_err());
    }
    
    #[test]
    fn test_display_name_validation() {
        // Test: Display name validation
        assert!(User::validate_display_name("Valid Name").is_ok());
        assert!(User::validate_display_name("").is_err());
        assert!(User::validate_display_name("a".repeat(256).as_str()).is_err());
        assert!(User::validate_display_name("Name\x00with\x01control").is_err());
    }
}
```

#### Credential Model Tests
```rust
#[cfg(test)]
mod credential_model_tests {
    use super::*;
    
    #[test]
    fn test_credential_creation() {
        // Test: Valid credential creation
        let credential = Credential::new(
            "user_id".to_string(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            "packed".to_string(),
        );
        assert_eq!(credential.user_id, "user_id");
        assert_eq!(credential.credential_id, vec![1, 2, 3, 4]);
        assert_eq!(credential.sign_count, 0);
        assert!(credential.is_active);
    }
    
    #[test]
    fn test_credential_id_validation() {
        // Test: Credential ID validation
        assert!(Credential::validate_credential_id(&vec![1, 2, 3, 4]).is_ok());
        assert!(Credential::validate_credential_id(&vec![]).is_err());
        assert!(Credential::validate_credential_id(&vec![0; 1025]).is_err());
    }
    
    #[test]
    fn test_counter_update() {
        // Test: Counter update logic
        let mut credential = get_test_credential();
        let old_counter = credential.sign_count;
        let result = credential.update_counter(123);
        assert!(result.is_ok());
        assert_eq!(credential.sign_count, 123);
        assert!(credential.sign_count > old_counter);
    }
    
    #[test]
    fn test_counter_regression_detection() {
        // Test: Counter regression detection
        let mut credential = get_test_credential();
        credential.sign_count = 100;
        let result = credential.update_counter(50);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CredentialError::CounterRegression));
    }
}
```

### 1.3 Utility Tests

#### Cryptographic Utility Tests
```rust
#[cfg(test)]
mod crypto_tests {
    use super::*;
    
    #[test]
    fn test_base64url_encoding() {
        // Test: Base64URL encoding/decoding
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data, &decoded[..]);
    }
    
    #[test]
    fn test_base64url_invalid_input() {
        // Test: Invalid Base64URL input
        assert!(base64url_decode("invalid!").is_err());
        assert!(base64url_decode("").is_err());
    }
    
    #[test]
    fn test_sha256_hashing() {
        // Test: SHA-256 hashing
        let data = b"test data";
        let hash1 = sha256_hash(data);
        let hash2 = sha256_hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 produces 32 bytes
    }
    
    #[test]
    fn test_constant_time_compare() {
        // Test: Constant-time comparison
        let data1 = b"secret data";
        let data2 = b"secret data";
        let data3 = b"different data";
        
        assert!(constant_time_compare(data1, data2));
        assert!(!constant_time_compare(data1, data3));
        
        // Test timing consistency (basic check)
        let start = Instant::now();
        for _ in 0..1000 {
            constant_time_compare(data1, data2);
        }
        let same_time = start.elapsed();
        
        let start = Instant::now();
        for _ in 0..1000 {
            constant_time_compare(data1, data3);
        }
        let diff_time = start.elapsed();
        
        // Times should be similar (within reasonable variance)
        let ratio = diff_time.as_nanos() as f64 / same_time.as_nanos() as f64;
        assert!(ratio < 2.0); // Should be within 2x
    }
}
```

## 2. Integration Test Specification

### 2.1 API Endpoint Tests

#### Registration Flow Tests
```rust
#[cfg(test)]
mod registration_integration_tests {
    use super::*;
    use actix_web::{test, App};
    
    #[actix_web::test]
    async fn test_registration_challenge_success() {
        // Test: Successful registration challenge generation
        let app = test::init_service(create_app()).await;
        let req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "displayName": "Test User",
                "userVerification": "preferred",
                "attestation": "direct"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert!(body["challenge"].is_string());
        assert!(body["rp"]["id"].is_string());
        assert!(body["user"]["id"].is_string());
    }
    
    #[actix_web::test]
    async fn test_registration_challenge_invalid_user() {
        // Test: Registration challenge with invalid user
        let app = test::init_service(create_app()).await;
        let req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_json(&serde_json::json!({
                "username": "",
                "displayName": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "error");
        assert_eq!(body["error"], "INVALID_USER");
    }
    
    #[actix_web::test]
    async fn test_registration_verification_success() {
        // Test: Successful registration verification
        let app = test::init_service(create_app()).await;
        
        // First, create a challenge
        let challenge_req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .to_request();
        
        let challenge_resp = test::call_service(&app, challenge_req).await;
        let challenge_body: serde_json::Value = test::read_body_json(challenge_resp).await;
        let challenge = challenge_body["challenge"].as_str().unwrap();
        
        // Then verify with valid attestation
        let verify_req = test::TestRequest::post()
            .uri("/webauthn/register/verify")
            .set_json(&serde_json::json!({
                "credential": create_valid_attestation_response(),
                "username": "test@example.com",
                "challenge": challenge
            }))
            .to_request();
        
        let verify_resp = test::call_service(&app, verify_req).await;
        assert_eq!(verify_resp.status(), 200);
        
        let verify_body: serde_json::Value = test::read_body_json(verify_resp).await;
        assert_eq!(verify_body["status"], "ok");
        assert!(verify_body["credentialId"].is_string());
    }
    
    #[actix_web::test]
    async fn test_registration_verification_invalid_attestation() {
        // Test: Registration verification with invalid attestation
        let app = test::init_service(create_app()).await;
        let req = test::TestRequest::post()
            .uri("/webauthn/register/verify")
            .set_json(&serde_json::json!({
                "credential": create_invalid_attestation_response(),
                "username": "test@example.com",
                "challenge": "invalid-challenge"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "error");
        assert_eq!(body["error"], "INVALID_ATTESTATION");
    }
}
```

#### Authentication Flow Tests
```rust
#[cfg(test)]
mod authentication_integration_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_authentication_challenge_success() {
        // Test: Successful authentication challenge generation
        let app = test::init_service(create_app()).await;
        
        // First, register a user and credential
        setup_test_user(&app).await;
        
        let req = test::TestRequest::post()
            .uri("/webauthn/authenticate/challenge")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "userVerification": "preferred"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert!(body["challenge"].is_string());
        assert!(body["allowCredentials"].is_array());
        assert!(body["allowCredentials"].as_array().unwrap().len() > 0);
    }
    
    #[actix_web::test]
    async fn test_authentication_challenge_no_credentials() {
        // Test: Authentication challenge for user with no credentials
        let app = test::init_service(create_app()).await;
        
        let req = test::TestRequest::post()
            .uri("/webauthn/authenticate/challenge")
            .set_json(&serde_json::json!({
                "username": "nonexistent@example.com"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "error");
        assert_eq!(body["error"], "USER_NOT_FOUND");
    }
    
    #[actix_web::test]
    async fn test_authentication_verification_success() {
        // Test: Successful authentication verification
        let app = test::init_service(create_app()).await;
        
        // Setup user and credential
        let (user, credential) = setup_test_user_with_credential(&app).await;
        
        // Get challenge
        let challenge_req = test::TestRequest::post()
            .uri("/webauthn/authenticate/challenge")
            .set_json(&serde_json::json!({
                "username": user.username
            }))
            .to_request();
        
        let challenge_resp = test::call_service(&app, challenge_req).await;
        let challenge_body: serde_json::Value = test::read_body_json(challenge_resp).await;
        let challenge = challenge_body["challenge"].as_str().unwrap();
        
        // Verify authentication
        let verify_req = test::TestRequest::post()
            .uri("/webauthn/authenticate/verify")
            .set_json(&serde_json::json!({
                "credential": create_valid_assertion_response(&credential, challenge),
                "username": user.username,
                "challenge": challenge
            }))
            .to_request();
        
        let verify_resp = test::call_service(&app, verify_req).await;
        assert_eq!(verify_resp.status(), 200);
        
        let verify_body: serde_json::Value = test::read_body_json(verify_resp).await;
        assert_eq!(verify_body["status"], "ok");
        assert!(verify_body["newCounter"].is_number());
    }
}
```

### 2.2 Database Integration Tests

```rust
#[cfg(test)]
mod database_integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_user_crud_operations() {
        // Test: User CRUD operations
        let pool = create_test_db_pool().await;
        
        // Create user
        let user = User::new("test@example.com", "Test User");
        let created_user = create_user(&pool, &user).await.unwrap();
        assert!(created_user.id.is_some());
        
        // Read user
        let retrieved_user = get_user_by_id(&pool, created_user.id.unwrap()).await.unwrap();
        assert_eq!(retrieved_user.username, user.username);
        
        // Update user
        let mut updated_user = retrieved_user;
        updated_user.display_name = "Updated Name".to_string();
        update_user(&pool, &updated_user).await.unwrap();
        
        let check_user = get_user_by_id(&pool, updated_user.id.unwrap()).await.unwrap();
        assert_eq!(check_user.display_name, "Updated Name");
        
        // Delete user
        delete_user(&pool, updated_user.id.unwrap()).await.unwrap();
        let deleted_user = get_user_by_id(&pool, updated_user.id.unwrap()).await;
        assert!(deleted_user.is_err());
    }
    
    #[tokio::test]
    async fn test_credential_crud_operations() {
        // Test: Credential CRUD operations
        let pool = create_test_db_pool().await;
        let user = create_test_user(&pool).await;
        
        // Create credential
        let credential = Credential::new(
            user.id.unwrap().to_string(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            "packed".to_string(),
        );
        let created_credential = create_credential(&pool, &credential).await.unwrap();
        assert!(created_credential.id.is_some());
        
        // Read credential
        let retrieved_credential = get_credential_by_id(&pool, created_credential.id.unwrap()).await.unwrap();
        assert_eq!(retrieved_credential.user_id, credential.user_id);
        
        // Update credential counter
        let mut updated_credential = retrieved_credential;
        updated_credential.sign_count = 123;
        update_credential(&pool, &updated_credential).await.unwrap();
        
        let check_credential = get_credential_by_id(&pool, updated_credential.id.unwrap()).await.unwrap();
        assert_eq!(check_credential.sign_count, 123);
        
        // Delete credential
        delete_credential(&pool, updated_credential.id.unwrap()).await.unwrap();
        let deleted_credential = get_credential_by_id(&pool, updated_credential.id.unwrap()).await;
        assert!(deleted_credential.is_err());
    }
    
    #[tokio::test]
    async fn test_challenge_crud_operations() {
        // Test: Challenge CRUD operations
        let pool = create_test_db_pool().await;
        
        // Create challenge
        let challenge = Challenge::new(
            "user_id".to_string(),
            ChallengeType::Registration,
            Duration::minutes(5),
        );
        let created_challenge = create_challenge(&pool, &challenge).await.unwrap();
        assert!(created_challenge.id.is_some());
        
        // Read challenge
        let retrieved_challenge = get_challenge_by_id(&pool, created_challenge.id.unwrap()).await.unwrap();
        assert_eq!(retrieved_challenge.challenge_type, ChallengeType::Registration);
        
        // Mark challenge as used
        mark_challenge_used(&pool, created_challenge.id.unwrap()).await.unwrap();
        
        let check_challenge = get_challenge_by_id(&pool, created_challenge.id.unwrap()).await.unwrap();
        assert!(check_challenge.used);
        
        // Clean up expired challenges
        let cleaned_count = cleanup_expired_challenges(&pool).await.unwrap();
        assert!(cleaned_count >= 0);
    }
}
```

## 3. Security Test Specification

### 3.1 Attack Vector Tests

#### Replay Attack Tests
```rust
#[cfg(test)]
mod replay_attack_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_challenge_reuse_prevention() {
        // Test: Challenge reuse prevention
        let app = test::init_service(create_app()).await;
        
        // Get registration challenge
        let challenge_req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .to_request();
        
        let challenge_resp = test::call_service(&app, challenge_req).await;
        let challenge_body: serde_json::Value = test::read_body_json(challenge_resp).await;
        let challenge = challenge_body["challenge"].as_str().unwrap();
        
        // Use challenge successfully first time
        let verify_req1 = test::TestRequest::post()
            .uri("/webauthn/register/verify")
            .set_json(&serde_json::json!({
                "credential": create_valid_attestation_response(),
                "username": "test@example.com",
                "challenge": challenge
            }))
            .to_request();
        
        let verify_resp1 = test::call_service(&app, verify_req1).await;
        assert_eq!(verify_resp1.status(), 200);
        
        // Try to reuse same challenge (should fail)
        let verify_req2 = test::TestRequest::post()
            .uri("/webauthn/register/verify")
            .set_json(&serde_json::json!({
                "credential": create_valid_attestation_response(),
                "username": "test@example.com",
                "challenge": challenge
            }))
            .to_request();
        
        let verify_resp2 = test::call_service(&app, verify_req2).await;
        assert_eq!(verify_resp2.status(), 400);
        
        let body: serde_json::Value = test::read_body_json(verify_resp2).await;
        assert_eq!(body["error"], "CHALLENGE_ALREADY_USED");
    }
    
    #[actix_web::test]
    async fn test_expired_challenge_rejection() {
        // Test: Expired challenge rejection
        let app = test::init_service(create_app()).await;
        
        // Create expired challenge manually
        let expired_challenge = create_expired_challenge().await;
        
        let verify_req = test::TestRequest::post()
            .uri("/webauthn/register/verify")
            .set_json(&serde_json::json!({
                "credential": create_valid_attestation_response(),
                "username": "test@example.com",
                "challenge": expired_challenge
            }))
            .to_request();
        
        let resp = test::call_service(&app, verify_req).await;
        assert_eq!(resp.status(), 400);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "CHALLENGE_EXPIRED");
    }
}
```

#### Input Validation Tests
```rust
#[cfg(test)]
mod input_validation_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_malformed_json_rejection() {
        // Test: Malformed JSON rejection
        let app = test::init_service(create_app()).await;
        let req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_payload("invalid json".to_string())
            .header("content-type", "application/json")
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
    
    #[actix_web::test]
    async fn test_sql_injection_prevention() {
        // Test: SQL injection prevention
        let app = test::init_service(create_app()).await;
        let malicious_username = "'; DROP TABLE users; --";
        
        let req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_json(&serde_json::json!({
                "username": malicious_username,
                "displayName": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        // Should return validation error, not crash
        assert!(resp.status().is_client_error());
    }
    
    #[actix_web::test]
    async fn test_xss_prevention() {
        // Test: XSS prevention in display names
        let app = test::init_service(create_app()).await;
        let xss_payload = "<script>alert('xss')</script>";
        
        let req = test::TestRequest::post()
            .uri("/webauthn/register/challenge")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "displayName": xss_payload
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        // Should either reject or sanitize
        if resp.status().is_success() {
            let body: serde_json::Value = test::read_body_json(resp).await;
            let display_name = body["user"]["displayName"].as_str().unwrap();
            assert!(!display_name.contains("<script>"));
        }
    }
}
```

#### Cryptographic Attack Tests
```rust
#[cfg(test)]
mod cryptographic_attack_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_signature_forgery_prevention() {
        // Test: Signature forgery prevention
        let app = test::init_service(create_app()).await;
        
        let forged_attestation = create_forged_attestation();
        let req = test::TestRequest::post()
            .uri("/webauthn/register/verify")
            .set_json(&serde_json::json!({
                "credential": forged_attestation,
                "username": "test@example.com",
                "challenge": "valid-challenge"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "INVALID_SIGNATURE");
    }
    
    #[actix_web::test]
    async fn test_timing_attack_resistance() {
        // Test: Timing attack resistance in credential lookup
        let app = test::init_service(create_app()).await;
        
        // Measure time for existing credential
        let start = Instant::now();
        let req1 = test::TestRequest::post()
            .uri("/webauthn/authenticate/challenge")
            .set_json(&serde_json::json!({
                "username": "existing@example.com"
            }))
            .to_request();
        let _ = test::call_service(&app, req1).await;
        let existing_time = start.elapsed();
        
        // Measure time for non-existing credential
        let start = Instant::now();
        let req2 = test::TestRequest::post()
            .uri("/webauthn/authenticate/challenge")
            .set_json(&serde_json::json!({
                "username": "nonexistent@example.com"
            }))
            .to_request();
        let _ = test::call_service(&app, req2).await;
        let nonexistent_time = start.elapsed();
        
        // Times should be similar (within reasonable variance)
        let ratio = nonexistent_time.as_millis() as f64 / existing_time.as_millis() as f64;
        assert!(ratio < 3.0); // Should be within 3x
    }
}
```

### 3.2 Compliance Tests

#### FIDO2 Conformance Tests
```rust
#[cfg(test)]
mod fido2_conformance_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_rp_id_validation() {
        // Test: RP ID validation according to FIDO2 spec
        let test_cases = vec![
            ("example.com", true),
            ("sub.example.com", true),
            ("example.com:8080", false), // Port not allowed in RP ID
            ("", false),
            ("invalid..domain", false),
            (".example.com", false),
            ("example.com.", false),
        ];
        
        for (rp_id, should_be_valid) in test_cases {
            let result = validate_rp_id(rp_id);
            assert_eq!(result.is_ok(), should_be_valid, "RP ID: {}", rp_id);
        }
    }
    
    #[actix_web::test]
    async fn test_origin_validation() {
        // Test: Origin validation according to FIDO2 spec
        let test_cases = vec![
            ("https://example.com", "example.com", true),
            ("https://sub.example.com", "example.com", true),
            ("http://localhost", "localhost", true), // Development exception
            ("https://example.com:8443", "example.com", true),
            ("http://example.com", "example.com", false), // HTTP not allowed
            ("https://evil.com", "example.com", false),
            ("ftp://example.com", "example.com", false),
        ];
        
        for (origin, rp_id, should_be_valid) in test_cases {
            let result = validate_origin(origin, rp_id);
            assert_eq!(result.is_ok(), should_be_valid, "Origin: {}, RP ID: {}", origin, rp_id);
        }
    }
    
    #[actix_web::test]
    async fn test_attestation_format_compliance() {
        // Test: Attestation format compliance
        let supported_formats = vec!["packed", "fido-u2f", "none", "android-key", "android-safetynet"];
        
        for format in supported_formats {
            let attestation = create_attestation_with_format(format);
            let result = verify_attestation_format(&attestation).await;
            assert!(result.is_ok(), "Format: {}", format);
        }
        
        // Test unsupported format
        let unsupported_attestation = create_attestation_with_format("unsupported");
        let result = verify_attestation_format(&unsupported_attestation).await;
        assert!(result.is_err());
    }
    
    #[actix_web::test]
    async fn test_cose_key_compliance() {
        // Test: COSE key compliance
        let valid_keys = vec![
            (CoseKeyType::EC2, CoseAlgorithm::ES256, Curve::P256),
            (CoseKeyType::EC2, CoseAlgorithm::ES384, Curve::P384),
            (CoseKeyType::RSA, CoseAlgorithm::RS256, None),
        ];
        
        for (key_type, algorithm, curve) in valid_keys {
            let cose_key = create_cose_key(key_type, algorithm, curve);
            let result = validate_cose_key(&cose_key);
            assert!(result.is_ok(), "Key type: {:?}, Algorithm: {:?}", key_type, algorithm);
        }
    }
}
```

## 4. Performance Test Specification

### 4.1 Load Testing

```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    
    #[tokio::test]
    async fn test_concurrent_registration_challenges() {
        // Test: Concurrent registration challenge generation
        let app = Arc::new(test::init_service(create_app()).await);
        let semaphore = Arc::new(Semaphore::new(100)); // Limit concurrent requests
        let mut handles = vec![];
        
        for i in 0..1000 {
            let app_clone = Arc::clone(&app);
            let semaphore_clone = Arc::clone(&semaphore);
            
            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                
                let req = test::TestRequest::post()
                    .uri("/webauthn/register/challenge")
                    .set_json(&serde_json::json!({
                        "username": format!("user{}@example.com", i),
                        "displayName": format!("User {}", i)
                    }))
                    .to_request();
                
                let start = Instant::now();
                let resp = test::call_service(&*app_clone, req).await;
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
        
        assert!(success_count >= 950); // 95% success rate
        assert!(total_duration / 1000 < Duration::from_millis(100)); // Average < 100ms
        assert!(max_duration < Duration::from_millis(500)); // Max < 500ms
    }
    
    #[tokio::test]
    async fn test_memory_usage_stability() {
        // Test: Memory usage stability under load
        let app = test::init_service(create_app()).await;
        let initial_memory = get_memory_usage();
        
        // Generate 10,000 challenges
        for i in 0..10000 {
            let req = test::TestRequest::post()
                .uri("/webauthn/register/challenge")
                .set_json(&serde_json::json!({
                    "username": format!("user{}@example.com", i),
                    "displayName": format!("User {}", i)
                }))
                .to_request();
            
            let _ = test::call_service(&app, req).await;
        }
        
        // Force garbage collection
        tokio::task::yield_now().await;
        
        let final_memory = get_memory_usage();
        let memory_increase = final_memory - initial_memory;
        
        // Memory increase should be reasonable (< 100MB)
        assert!(memory_increase < 100 * 1024 * 1024);
    }
}
```

## 5. Test Coverage Requirements

### 5.1 Coverage Targets

| Component | Target Coverage | Measurement |
|-----------|----------------|-------------|
| **WebAuthn Service** | 98% | Line + Branch |
| **Models** | 95% | Line + Branch |
| **Controllers** | 100% | Line + Branch |
| **Middleware** | 95% | Line + Branch |
| **Utilities** | 90% | Line + Branch |
| **Database Operations** | 95% | Line + Branch |
| **Error Handling** | 100% | Line + Branch |

### 5.2 Coverage Measurement

```bash
# Install coverage tools
cargo install cargo-tarpaulin

# Run coverage analysis
cargo tarpaulin --out Html --output-dir coverage/

# Generate coverage report
cargo tarpaulin --out Json --output-dir coverage/

# Check specific modules
cargo tarpaulin --lib --modules fido_server::webauthn
cargo tarpaulin --lib --modules fido_server::models
```

### 5.3 Continuous Integration Coverage

```yaml
# .github/workflows/test.yml
name: Test Coverage
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run tests with coverage
        run: |
          cargo tarpaulin --out Xml --output-dir coverage/
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: coverage/cobertura.xml
          fail_ci_if_error: true
```

## 6. Test Data Management

### 6.1 Test Data Factories

```rust
// tests/factories/mod.rs
pub mod user_factory;
pub mod credential_factory;
pub mod challenge_factory;
pub mod attestation_factory;

// tests/factories/user_factory.rs
use fido_server::models::User;

pub fn create_test_user() -> User {
    User::new(
        format!("test{}@example.com", uuid::Uuid::new_v4()),
        "Test User".to_string(),
    )
}

pub fn create_user_with_email(email: &str) -> User {
    User::new(email.to_string(), "Test User".to_string())
}
```

### 6.2 Test Database Setup

```rust
// tests/common/database.rs
use sqlx::PgPool;

pub async fn create_test_db_pool() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/fido_server_test".to_string());
    
    let pool = PgPool::connect(&database_url).await.unwrap();
    
    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    
    // Clean database before each test
    cleanup_database(&pool).await;
    
    pool
}

async fn cleanup_database(pool: &PgPool) {
    sqlx::query("TRUNCATE TABLE audit_logs, challenges, credentials, users RESTART IDENTITY CASCADE")
        .execute(pool)
        .await
        .unwrap();
}
```

This comprehensive test specification ensures thorough testing of all FIDO2/WebAuthn functionality with proper security validation, compliance checking, and performance verification.