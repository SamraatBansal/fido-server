# Test-Driven Development Plan for FIDO2/WebAuthn Server

## Overview

This document outlines a comprehensive TDD approach for implementing the FIDO2/WebAuthn Relying Party Server, organized by test categories and implementation phases.

## Test Organization Structure

```
tests/
├── unit/                      # Component-level tests
│   ├── models/
│   ├── handlers/
│   ├── storage/
│   └── security/
├── integration/               # End-to-end flow tests
│   ├── registration_flow/
│   ├── authentication_flow/
│   └── error_handling/
├── security/                  # Security-focused tests
│   ├── attack_simulation/
│   ├── input_validation/
│   └── rate_limiting/
├── conformance/               # FIDO Alliance compliance tests
│   ├── fido2_spec/
│   ├── webauthn_spec/
│   └── test_vectors/
└── performance/               # Load and stress tests
    ├── load_testing/
    └── stress_testing/
```

## Phase 1: Unit Tests for Core Components

### 1.1 Challenge Management Tests

**File:** `tests/unit/security/challenge_tests.rs`

```rust
#[cfg(test)]
mod challenge_tests {
    use super::*;
    use crate::security::challenge::*;

    #[test]
    fn test_challenge_generation_entropy() {
        // Test: Challenge must have at least 128 bits of entropy
        let challenge = generate_challenge();
        assert!(challenge.len() >= 16); // 128 bits = 16 bytes
        
        // Test: Challenges must be unique
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_challenge_expiration() {
        // Test: Challenges expire after configured time
        let challenge_store = ChallengeStore::new();
        let challenge = challenge_store.create_challenge(
            "user123", 
            ChallengeType::Registration,
            Duration::from_secs(300)
        ).unwrap();
        
        // Should be valid immediately
        assert!(challenge_store.validate_challenge(&challenge.challenge).is_ok());
        
        // Mock time advance
        challenge_store.advance_time(Duration::from_secs(301));
        
        // Should be expired
        assert!(challenge_store.validate_challenge(&challenge.challenge).is_err());
    }

    #[test]
    fn test_challenge_replay_protection() {
        // Test: Challenges can only be used once
        let challenge_store = ChallengeStore::new();
        let challenge = challenge_store.create_challenge(
            "user123",
            ChallengeType::Registration, 
            Duration::from_secs(300)
        ).unwrap();
        
        // First use should succeed
        assert!(challenge_store.consume_challenge(&challenge.challenge).is_ok());
        
        // Second use should fail
        assert!(challenge_store.consume_challenge(&challenge.challenge).is_err());
    }

    #[test]
    fn test_challenge_rate_limiting() {
        // Test: Rate limiting for challenge generation
        let challenge_store = ChallengeStore::new();
        
        // Generate up to the limit
        for _ in 0..5 {
            assert!(challenge_store.create_challenge(
                "user123",
                ChallengeType::Registration,
                Duration::from_secs(300)
            ).is_ok());
        }
        
        // Next attempt should be rate limited
        assert!(challenge_store.create_challenge(
            "user123",
            ChallengeType::Registration,
            Duration::from_secs(300)
        ).is_err());
    }
}
```

### 1.2 Credential Storage Tests

**File:** `tests/unit/storage/credential_tests.rs`

```rust
#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        // Test: Valid credential creation
        let storage = CredentialStorage::new();
        let credential = Credential {
            id: CredentialId::new(b"test_credential_id"),
            user_id: UserId::new(b"user123"),
            public_key: PublicKey::from_bytes(&get_test_public_key()),
            counter: 0,
            aaguid: Some(Uuid::new_v4()),
            transports: vec![Transport::Usb, Transport::Nfc],
        };
        
        let result = storage.store_credential(credential.clone());
        assert!(result.is_ok());
        
        // Verify credential can be retrieved
        let retrieved = storage.get_credential(&credential.id).unwrap();
        assert_eq!(retrieved.id, credential.id);
        assert_eq!(retrieved.user_id, credential.user_id);
    }

    #[test]
    fn test_credential_uniqueness() {
        // Test: Duplicate credential IDs are rejected
        let storage = CredentialStorage::new();
        let credential_id = CredentialId::new(b"duplicate_id");
        
        let credential1 = Credential {
            id: credential_id.clone(),
            user_id: UserId::new(b"user1"),
            public_key: PublicKey::from_bytes(&get_test_public_key()),
            counter: 0,
            aaguid: None,
            transports: vec![],
        };
        
        let credential2 = Credential {
            id: credential_id.clone(),
            user_id: UserId::new(b"user2"),
            public_key: PublicKey::from_bytes(&get_test_public_key()),
            counter: 0,
            aaguid: None,
            transports: vec![],
        };
        
        // First credential should succeed
        assert!(storage.store_credential(credential1).is_ok());
        
        // Second credential with same ID should fail
        assert!(storage.store_credential(credential2).is_err());
    }

    #[test]
    fn test_counter_validation() {
        // Test: Counter must increase monotonically
        let storage = CredentialStorage::new();
        let credential_id = CredentialId::new(b"counter_test");
        
        // Store initial credential with counter = 5
        let credential = Credential {
            id: credential_id.clone(),
            user_id: UserId::new(b"user123"),
            public_key: PublicKey::from_bytes(&get_test_public_key()),
            counter: 5,
            aaguid: None,
            transports: vec![],
        };
        storage.store_credential(credential).unwrap();
        
        // Update with higher counter should succeed
        assert!(storage.update_counter(&credential_id, 6).is_ok());
        
        // Update with lower counter should fail (cloned authenticator)
        assert!(storage.update_counter(&credential_id, 4).is_err());
        
        // Update with same counter should succeed (counter 0 case)
        assert!(storage.update_counter(&credential_id, 6).is_ok());
    }

    #[test]
    fn test_user_credential_limits() {
        // Test: Maximum credentials per user enforcement
        let storage = CredentialStorage::new();
        let user_id = UserId::new(b"limited_user");
        
        // Add maximum allowed credentials (e.g., 10)
        for i in 0..10 {
            let credential = Credential {
                id: CredentialId::new(&format!("cred_{}", i).as_bytes()),
                user_id: user_id.clone(),
                public_key: PublicKey::from_bytes(&get_test_public_key()),
                counter: 0,
                aaguid: None,
                transports: vec![],
            };
            assert!(storage.store_credential(credential).is_ok());
        }
        
        // 11th credential should be rejected
        let overflow_credential = Credential {
            id: CredentialId::new(b"overflow_cred"),
            user_id: user_id.clone(),
            public_key: PublicKey::from_bytes(&get_test_public_key()),
            counter: 0,
            aaguid: None,
            transports: vec![],
        };
        assert!(storage.store_credential(overflow_credential).is_err());
    }
}
```

### 1.3 Input Validation Tests

**File:** `tests/unit/security/validation_tests.rs`

```rust
#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        let validator = InputValidator::new();
        
        // Valid usernames
        assert!(validator.validate_username("alice").is_ok());
        assert!(validator.validate_username("user123").is_ok());
        assert!(validator.validate_username("test.user@example.com").is_ok());
        
        // Invalid usernames
        assert!(validator.validate_username("").is_err());           // Empty
        assert!(validator.validate_username("ab").is_err());         // Too short
        assert!(validator.validate_username(&"a".repeat(256)).is_err()); // Too long
        assert!(validator.validate_username("admin").is_err());      // Reserved
        assert!(validator.validate_username("user<script>").is_err()); // Injection
    }

    #[test]
    fn test_origin_validation() {
        let validator = InputValidator::new();
        validator.set_allowed_origins(vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ]);
        
        // Valid origins
        assert!(validator.validate_origin("https://example.com").is_ok());
        assert!(validator.validate_origin("https://app.example.com").is_ok());
        
        // Invalid origins
        assert!(validator.validate_origin("http://example.com").is_err());   // HTTP
        assert!(validator.validate_origin("https://evil.com").is_err());     // Unknown
        assert!(validator.validate_origin("https://example.com:8080").is_err()); // Port
        assert!(validator.validate_origin("").is_err());                     // Empty
    }

    #[test]
    fn test_base64url_validation() {
        let validator = InputValidator::new();
        
        // Valid base64url
        assert!(validator.validate_base64url("dGVzdA").is_ok());
        assert!(validator.validate_base64url("dGVzdF9kYXRh").is_ok());
        
        // Invalid base64url
        assert!(validator.validate_base64url("test+data").is_err());  // Standard base64
        assert!(validator.validate_base64url("test=data").is_err());  // Padding
        assert!(validator.validate_base64url("test data").is_err());  // Spaces
        assert!(validator.validate_base64url("").is_err());           // Empty
    }

    #[test]
    fn test_request_size_limits() {
        let validator = InputValidator::new();
        
        let small_request = RegistrationRequest {
            username: "test".to_string(),
            display_name: "Test User".to_string(),
            // ... other fields
        };
        assert!(validator.validate_request_size(&small_request).is_ok());
        
        let large_request = RegistrationRequest {
            username: "a".repeat(1000000), // 1MB username
            display_name: "Test User".to_string(),
            // ... other fields
        };
        assert!(validator.validate_request_size(&large_request).is_err());
    }
}
```

## Phase 2: Integration Tests for Complete Flows

### 2.1 Registration Flow Tests

**File:** `tests/integration/registration_flow.rs`

```rust
#[cfg(test)]
mod registration_flow_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_registration_flow() {
        // Setup test server
        let server = test_server().await;
        
        // Step 1: Begin registration
        let begin_req = json!({
            "username": "test_user",
            "displayName": "Test User",
            "authenticatorSelection": {
                "userVerification": "preferred"
            },
            "attestation": "none"
        });
        
        let begin_resp = server.post("/fido2/attestation/options")
            .json(&begin_req)
            .send()
            .await;
        
        assert_eq!(begin_resp.status(), 200);
        let options: PublicKeyCredentialCreationOptions = begin_resp.json().await;
        
        // Validate response structure
        assert!(!options.challenge.is_empty());
        assert_eq!(options.rp.id, "localhost");
        assert_eq!(options.user.name, "test_user");
        assert!(!options.pub_key_cred_params.is_empty());
        
        // Step 2: Generate test attestation
        let attestation_response = generate_test_attestation(&options);
        
        // Step 3: Complete registration
        let complete_resp = server.post("/fido2/attestation/result")
            .json(&attestation_response)
            .send()
            .await;
        
        assert_eq!(complete_resp.status(), 200);
        let result: AttestationResult = complete_resp.json().await;
        assert_eq!(result.status, "ok");
        assert!(!result.credential_id.is_empty());
    }

    #[tokio::test]
    async fn test_registration_with_user_verification_required() {
        let server = test_server().await;
        
        let begin_req = json!({
            "username": "uv_test_user",
            "displayName": "UV Test User", 
            "authenticatorSelection": {
                "userVerification": "required"
            }
        });
        
        let begin_resp = server.post("/fido2/attestation/options")
            .json(&begin_req)
            .send()
            .await;
            
        let options: PublicKeyCredentialCreationOptions = begin_resp.json().await;
        assert_eq!(options.authenticator_selection.user_verification, "required");
        
        // Generate attestation without UV flag set
        let mut attestation_response = generate_test_attestation(&options);
        attestation_response.set_user_verified(false);
        
        let complete_resp = server.post("/fido2/attestation/result")
            .json(&attestation_response)
            .send()
            .await;
            
        // Should fail due to missing user verification
        assert_eq!(complete_resp.status(), 400);
        let error: ErrorResponse = complete_resp.json().await;
        assert_eq!(error.status, "failed");
        assert!(error.error_message.contains("User verification required"));
    }

    #[tokio::test]
    async fn test_registration_duplicate_credential() {
        let server = test_server().await;
        
        // First registration
        let options1 = register_begin(&server, "duplicate_test").await;
        let attestation1 = generate_test_attestation(&options1);
        let result1 = register_complete(&server, &attestation1).await;
        assert_eq!(result1.status, "ok");
        
        // Second registration with same credential ID
        let options2 = register_begin(&server, "duplicate_test").await;
        let mut attestation2 = generate_test_attestation(&options2);
        attestation2.set_credential_id(&attestation1.get_credential_id());
        
        let complete_resp = server.post("/fido2/attestation/result")
            .json(&attestation2)
            .send()
            .await;
            
        // Should fail due to duplicate credential
        assert_eq!(complete_resp.status(), 409);
    }

    #[tokio::test]
    async fn test_registration_challenge_expiration() {
        let server = test_server().await;
        
        // Begin registration
        let options = register_begin(&server, "expire_test").await;
        
        // Wait for challenge to expire (mock time advancement)
        server.advance_time(Duration::from_secs(301)).await;
        
        // Try to complete with expired challenge
        let attestation_response = generate_test_attestation(&options);
        let complete_resp = server.post("/fido2/attestation/result")
            .json(&attestation_response)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 400);
        let error: ErrorResponse = complete_resp.json().await;
        assert!(error.error_message.contains("Challenge expired"));
    }
}
```

### 2.2 Authentication Flow Tests

**File:** `tests/integration/authentication_flow.rs`

```rust
#[cfg(test)]
mod authentication_flow_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_authentication_flow() {
        let server = test_server().await;
        
        // Setup: Register a credential first
        let (user, credential) = setup_test_credential(&server).await;
        
        // Step 1: Begin authentication
        let begin_req = json!({
            "username": user.username
        });
        
        let begin_resp = server.post("/fido2/assertion/options")
            .json(&begin_req)
            .send()
            .await;
            
        assert_eq!(begin_resp.status(), 200);
        let options: PublicKeyCredentialRequestOptions = begin_resp.json().await;
        
        // Validate response
        assert!(!options.challenge.is_empty());
        assert_eq!(options.rp_id, "localhost");
        assert_eq!(options.allow_credentials.len(), 1);
        assert_eq!(options.allow_credentials[0].id, credential.id);
        
        // Step 2: Generate test assertion
        let assertion_response = generate_test_assertion(&options, &credential);
        
        // Step 3: Complete authentication
        let complete_resp = server.post("/fido2/assertion/result")
            .json(&assertion_response)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 200);
        let result: AssertionResult = complete_resp.json().await;
        assert_eq!(result.status, "ok");
        assert_eq!(result.credential_id, credential.id);
    }

    #[tokio::test]
    async fn test_authentication_with_resident_key() {
        let server = test_server().await;
        
        // Setup: Register resident key credential
        let (user, credential) = setup_resident_key_credential(&server).await;
        
        // Begin authentication without username (discoverable)
        let begin_req = json!({});
        
        let begin_resp = server.post("/fido2/assertion/options")
            .json(&begin_req)
            .send()
            .await;
            
        let options: PublicKeyCredentialRequestOptions = begin_resp.json().await;
        
        // Should have empty allowCredentials for discoverable auth
        assert!(options.allow_credentials.is_empty());
        
        // Generate assertion with user handle
        let mut assertion_response = generate_test_assertion(&options, &credential);
        assertion_response.set_user_handle(&user.id);
        
        let complete_resp = server.post("/fido2/assertion/result")
            .json(&assertion_response)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 200);
        let result: AssertionResult = complete_resp.json().await;
        assert_eq!(result.user_handle, user.id);
    }

    #[tokio::test]
    async fn test_authentication_counter_validation() {
        let server = test_server().await;
        let (user, credential) = setup_test_credential(&server).await;
        
        // First authentication (counter = 1)
        let options1 = auth_begin(&server, &user.username).await;
        let mut assertion1 = generate_test_assertion(&options1, &credential);
        assertion1.set_counter(1);
        
        let result1 = auth_complete(&server, &assertion1).await;
        assert_eq!(result1.status, "ok");
        assert_eq!(result1.signature_counter, 1);
        
        // Second authentication with same counter (should succeed)
        let options2 = auth_begin(&server, &user.username).await;
        let mut assertion2 = generate_test_assertion(&options2, &credential);
        assertion2.set_counter(1);
        
        let result2 = auth_complete(&server, &assertion2).await;
        assert_eq!(result2.status, "ok");
        
        // Third authentication with lower counter (should fail - cloned)
        let options3 = auth_begin(&server, &user.username).await;
        let mut assertion3 = generate_test_assertion(&options3, &credential);
        assertion3.set_counter(0);
        
        let complete_resp = server.post("/fido2/assertion/result")
            .json(&assertion3)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 400);
        let error: ErrorResponse = complete_resp.json().await;
        assert!(error.error_message.contains("counter decreased"));
    }
}
```

## Phase 3: Security Tests

### 3.1 Attack Simulation Tests

**File:** `tests/security/attack_simulation.rs`

```rust
#[cfg(test)]
mod attack_simulation_tests {
    use super::*;

    #[tokio::test]
    async fn test_replay_attack_prevention() {
        let server = test_server().await;
        let (user, credential) = setup_test_credential(&server).await;
        
        // Get authentication options
        let options = auth_begin(&server, &user.username).await;
        let assertion = generate_test_assertion(&options, &credential);
        
        // First authentication should succeed
        let result1 = auth_complete(&server, &assertion).await;
        assert_eq!(result1.status, "ok");
        
        // Replay the same assertion - should fail
        let complete_resp = server.post("/fido2/assertion/result")
            .json(&assertion)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 400);
        let error: ErrorResponse = complete_resp.json().await;
        assert!(error.error_message.contains("Challenge already used"));
    }

    #[tokio::test]
    async fn test_cross_origin_attack() {
        let server = test_server().await;
        
        // Register from legitimate origin
        let options = register_begin(&server, "cross_origin_test").await;
        let mut attestation = generate_test_attestation(&options);
        
        // Modify client data to use different origin
        attestation.set_origin("https://evil.com");
        
        let complete_resp = server.post("/fido2/attestation/result")
            .json(&attestation)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 400);
        let error: ErrorResponse = complete_resp.json().await;
        assert!(error.error_message.contains("Origin validation failed"));
    }

    #[tokio::test]
    async fn test_malformed_attestation_object() {
        let server = test_server().await;
        
        let options = register_begin(&server, "malformed_test").await;
        
        // Create malformed attestation response
        let malformed_response = json!({
            "id": "dGVzdF9jcmVk",
            "rawId": "dGVzdF9jcmVk",
            "response": {
                "clientDataJSON": "invalid_base64!!!",
                "attestationObject": "not_valid_cbor"
            },
            "type": "public-key"
        });
        
        let complete_resp = server.post("/fido2/attestation/result")
            .json(&malformed_response)
            .send()
            .await;
            
        assert_eq!(complete_resp.status(), 400);
        let error: ErrorResponse = complete_resp.json().await;
        assert!(error.error_message.contains("Invalid attestation object"));
    }

    #[tokio::test]
    async fn test_injection_attacks() {
        let server = test_server().await;
        
        // SQL injection attempt in username
        let sql_injection_req = json!({
            "username": "'; DROP TABLE users; --",
            "displayName": "SQL Injection Test"
        });
        
        let resp = server.post("/fido2/attestation/options")
            .json(&sql_injection_req)
            .send()
            .await;
            
        assert_eq!(resp.status(), 400);
        
        // XSS attempt in display name
        let xss_injection_req = json!({
            "username": "xss_test",
            "displayName": "<script>alert('xss')</script>"
        });
        
        let resp = server.post("/fido2/attestation/options")
            .json(&xss_injection_req)
            .send()
            .await;
            
        assert_eq!(resp.status(), 400);
    }
}
```

### 3.2 Rate Limiting Tests

**File:** `tests/security/rate_limiting.rs`

```rust
#[cfg(test)]
mod rate_limiting_tests {
    use super::*;

    #[tokio::test]
    async fn test_registration_rate_limiting() {
        let server = test_server().await;
        
        // Make requests up to the limit (e.g., 5 per minute)
        for i in 0..5 {
            let req = json!({
                "username": format!("rate_test_{}", i),
                "displayName": "Rate Test User"
            });
            
            let resp = server.post("/fido2/attestation/options")
                .json(&req)
                .send()
                .await;
                
            assert_eq!(resp.status(), 200);
        }
        
        // 6th request should be rate limited
        let req = json!({
            "username": "rate_test_6",
            "displayName": "Rate Test User"
        });
        
        let resp = server.post("/fido2/attestation/options")
            .json(&req)
            .send()
            .await;
            
        assert_eq!(resp.status(), 429);
        
        let headers = resp.headers();
        assert!(headers.contains_key("retry-after"));
    }

    #[tokio::test]
    async fn test_ip_based_rate_limiting() {
        let server = test_server().await;
        
        // Test rate limiting per IP address
        let client1 = server.client_with_ip("192.168.1.100");
        let client2 = server.client_with_ip("192.168.1.101");
        
        // Client1 hits rate limit
        for _ in 0..10 {
            let resp = client1.post("/fido2/attestation/options")
                .json(&json!({"username": "test", "displayName": "Test"}))
                .send()
                .await;
            // Some should succeed, last should fail
        }
        
        // Client2 should still work (different IP)
        let resp = client2.post("/fido2/attestation/options")
            .json(&json!({"username": "test2", "displayName": "Test2"}))
            .send()
            .await;
            
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_progressive_backoff() {
        let server = test_server().await;
        
        // First rate limit violation
        exceed_rate_limit(&server).await;
        
        let resp1 = server.post("/fido2/attestation/options")
            .json(&json!({"username": "backoff1", "displayName": "Test"}))
            .send()
            .await;
            
        assert_eq!(resp1.status(), 429);
        let retry_after_1: u64 = resp1.headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        
        // Continue violating after wait
        server.advance_time(Duration::from_secs(retry_after_1 + 1)).await;
        exceed_rate_limit(&server).await;
        
        let resp2 = server.post("/fido2/attestation/options")
            .json(&json!({"username": "backoff2", "displayName": "Test"}))
            .send()
            .await;
            
        let retry_after_2: u64 = resp2.headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        
        // Second backoff should be longer
        assert!(retry_after_2 > retry_after_1);
    }
}
```

## Phase 4: FIDO Alliance Conformance Tests

### 4.1 FIDO2 Specification Compliance

**File:** `tests/conformance/fido2_spec.rs`

```rust
#[cfg(test)]
mod fido2_conformance_tests {
    use super::*;

    #[tokio::test]
    async fn test_supported_algorithms() {
        let server = test_server().await;
        
        let resp = server.get("/fido2/attestation/metadata").send().await;
        assert_eq!(resp.status(), 200);
        
        let metadata: ServerMetadata = resp.json().await;
        
        // Must support required algorithms
        assert!(metadata.algorithms.contains(&-7));   // ES256
        assert!(metadata.algorithms.contains(&-257)); // RS256
        
        // Test registration with each supported algorithm
        for &alg in &metadata.algorithms {
            let options = register_begin(&server, &format!("alg_test_{}", alg)).await;
            
            // Verify algorithm is in pubKeyCredParams
            assert!(options.pub_key_cred_params.iter()
                .any(|param| param.alg == alg));
                
            // Complete registration with this algorithm
            let attestation = generate_test_attestation_with_alg(&options, alg);
            let result = register_complete(&server, &attestation).await;
            assert_eq!(result.status, "ok");
        }
    }

    #[tokio::test]
    async fn test_attestation_format_support() {
        let server = test_server().await;
        
        let metadata_resp = server.get("/fido2/attestation/metadata").send().await;
        let metadata: ServerMetadata = metadata_resp.json().await;
        
        // Test each supported attestation format
        for fmt in &metadata.attestation_formats {
            let options = register_begin(&server, &format!("fmt_test_{}", fmt)).await;
            
            let attestation = match fmt.as_str() {
                "packed" => generate_packed_attestation(&options),
                "tpm" => generate_tpm_attestation(&options),
                "android-key" => generate_android_key_attestation(&options),
                "android-safetynet" => generate_safetynet_attestation(&options),
                "fido-u2f" => generate_u2f_attestation(&options),
                "none" => generate_none_attestation(&options),
                _ => continue, // Skip unsupported formats in test
            };
            
            let result = register_complete(&server, &attestation).await;
            assert_eq!(result.status, "ok");
        }
    }

    #[tokio::test]
    async fn test_user_verification_combinations() {
        let server = test_server().await;
        
        let test_cases = vec![
            ("required", true, true),   // UV required, provided -> success
            ("required", false, false), // UV required, missing -> fail
            ("preferred", true, true),  // UV preferred, provided -> success  
            ("preferred", false, true), // UV preferred, missing -> success
            ("discouraged", false, true), // UV discouraged, missing -> success
            ("discouraged", true, true),  // UV discouraged, provided -> success
        ];
        
        for (requirement, uv_flag, should_succeed) in test_cases {
            let begin_req = json!({
                "username": format!("uv_test_{}", requirement),
                "displayName": "UV Test",
                "authenticatorSelection": {
                    "userVerification": requirement
                }
            });
            
            let options = server.post("/fido2/attestation/options")
                .json(&begin_req)
                .send()
                .await
                .json::<PublicKeyCredentialCreationOptions>()
                .await;
                
            let mut attestation = generate_test_attestation(&options);
            attestation.set_user_verified(uv_flag);
            
            let complete_resp = server.post("/fido2/attestation/result")
                .json(&attestation)
                .send()
                .await;
                
            if should_succeed {
                assert_eq!(complete_resp.status(), 200);
            } else {
                assert_eq!(complete_resp.status(), 400);
            }
        }
    }

    #[tokio::test]
    async fn test_resident_key_support() {
        let server = test_server().await;
        
        // Test resident key required
        let rk_required_req = json!({
            "username": "rk_required_test",
            "displayName": "RK Required Test",
            "authenticatorSelection": {
                "residentKey": "required",
                "requireResidentKey": true
            }
        });
        
        let options = server.post("/fido2/attestation/options")
            .json(&rk_required_req)
            .send()
            .await
            .json::<PublicKeyCredentialCreationOptions>()
            .await;
            
        assert_eq!(options.authenticator_selection.resident_key, "required");
        assert_eq!(options.authenticator_selection.require_resident_key, true);
        
        // Generate attestation with resident key capability
        let attestation = generate_resident_key_attestation(&options);
        let result = register_complete(&server, &attestation).await;
        assert_eq!(result.status, "ok");
        
        // Test discoverable authentication
        let auth_options = server.post("/fido2/assertion/options")
            .json(&json!({})) // No username for discoverable
            .send()
            .await
            .json::<PublicKeyCredentialRequestOptions>()
            .await;
            
        assert!(auth_options.allow_credentials.is_empty());
    }
}
```

### 4.2 Test Vector Validation

**File:** `tests/conformance/test_vectors.rs`

```rust
#[cfg(test)]
mod test_vector_tests {
    use super::*;
    
    // Load official FIDO test vectors
    const FIDO_TEST_VECTORS: &str = include_str!("../test_data/fido_test_vectors.json");

    #[tokio::test]
    async fn test_official_registration_vectors() {
        let server = test_server().await;
        let test_vectors: TestVectors = serde_json::from_str(FIDO_TEST_VECTORS).unwrap();
        
        for vector in test_vectors.registration_vectors {
            // Begin registration with vector parameters
            let options = register_begin(&server, &vector.username).await;
            
            // Use vector's attestation response
            let complete_resp = server.post("/fido2/attestation/result")
                .json(&vector.attestation_response)
                .send()
                .await;
                
            // Validate expected outcome
            if vector.should_succeed {
                assert_eq!(complete_resp.status(), 200);
                let result: AttestationResult = complete_resp.json().await;
                assert_eq!(result.status, "ok");
            } else {
                assert_ne!(complete_resp.status(), 200);
            }
        }
    }

    #[tokio::test]
    async fn test_official_authentication_vectors() {
        let server = test_server().await;
        let test_vectors: TestVectors = serde_json::from_str(FIDO_TEST_VECTORS).unwrap();
        
        for vector in test_vectors.authentication_vectors {
            // Setup credential from vector
            setup_credential_from_vector(&server, &vector).await;
            
            // Begin authentication
            let options = auth_begin(&server, &vector.username).await;
            
            // Use vector's assertion response
            let complete_resp = server.post("/fido2/assertion/result")
                .json(&vector.assertion_response)
                .send()
                .await;
                
            // Validate expected outcome
            if vector.should_succeed {
                assert_eq!(complete_resp.status(), 200);
                let result: AssertionResult = complete_resp.json().await;
                assert_eq!(result.status, "ok");
            } else {
                assert_ne!(complete_resp.status(), 200);
            }
        }
    }
}
```

## Test Execution Strategy

### Continuous Integration Pipeline

```yaml
# .github/workflows/test.yml
name: FIDO2 WebAuthn Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run unit tests
        run: cargo test --lib --bins

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3
      - name: Run integration tests
        run: cargo test --test integration

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security tests
        run: cargo test --test security

  conformance-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run FIDO conformance tests
        run: cargo test --test conformance

  performance-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run performance tests
        run: cargo test --test performance --release
```

### Test Coverage Requirements

| Test Category | Minimum Coverage | Target Coverage |
|---------------|------------------|-----------------|
| Unit Tests | 90% | 95% |
| Integration Tests | 80% | 90% |
| Security Tests | 100% | 100% |
| Conformance Tests | 100% | 100% |

### Test Data Management

```rust
// Test data factory for consistent test setup
pub struct TestDataFactory {
    users: Vec<TestUser>,
    credentials: Vec<TestCredential>,
    challenges: Vec<TestChallenge>,
}

impl TestDataFactory {
    pub fn new() -> Self {
        Self {
            users: load_test_users(),
            credentials: load_test_credentials(),
            challenges: load_test_challenges(),
        }
    }
    
    pub fn create_test_user(&self, username: &str) -> TestUser {
        // Create consistent test user
    }
    
    pub fn create_test_credential(&self, user: &TestUser) -> TestCredential {
        // Create valid test credential
    }
}
```

This comprehensive TDD plan ensures security-first development with full FIDO2/WebAuthn specification compliance through systematic testing at all levels.