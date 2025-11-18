# FIDO2/WebAuthn Test Planning Strategy

## 1. Test Case Categories & Priority Matrix

### 1.1 Critical Security Tests (Priority 1)
These tests MUST pass for FIDO2 compliance and security certification.

#### Challenge Management Tests
```rust
#[cfg(test)]
mod challenge_security_tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_entropy_requirements() {
        // Test: Challenge must have ≥128 bits of entropy
        let challenge = generate_challenge().await;
        assert!(challenge.len() >= 16, "Challenge must be at least 16 bytes");
        
        // Test: Challenges should be cryptographically random
        let challenge2 = generate_challenge().await;
        assert_ne!(challenge, challenge2, "Consecutive challenges must be unique");
    }

    #[tokio::test]
    async fn test_challenge_replay_prevention() {
        // Test: Challenge can only be used once
        let challenge = generate_challenge().await;
        let result1 = validate_challenge(&challenge).await;
        assert!(result1.is_ok(), "First use should succeed");
        
        let result2 = validate_challenge(&challenge).await;
        assert!(result2.is_err(), "Second use should fail");
        assert_eq!(result2.unwrap_err(), SecurityError::ChallengeAlreadyUsed);
    }

    #[tokio::test]
    async fn test_challenge_expiration() {
        // Test: Expired challenges should be rejected
        let expired_challenge = create_expired_challenge().await;
        let result = validate_challenge(&expired_challenge).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SecurityError::ChallengeExpired);
    }
}
```

#### Origin Validation Tests
```rust
#[cfg(test)]
mod origin_validation_tests {
    #[tokio::test]
    async fn test_strict_origin_matching() {
        let validator = OriginValidator::new(&["https://example.com"]);
        
        // Test: Exact match should pass
        assert!(validator.validate_origin("https://example.com", "example.com").is_ok());
        
        // Test: Subdomain should fail in strict mode
        assert!(validator.validate_origin("https://sub.example.com", "example.com").is_err());
        
        // Test: Different scheme should fail
        assert!(validator.validate_origin("http://example.com", "example.com").is_err());
        
        // Test: Port mismatch should fail
        assert!(validator.validate_origin("https://example.com:8080", "example.com").is_err());
    }

    #[tokio::test]
    async fn test_rp_id_origin_binding() {
        // Test: Origin must be consistent with RP ID
        let test_cases = vec![
            ("https://example.com", "example.com", true),
            ("https://sub.example.com", "example.com", false),
            ("https://evil.com", "example.com", false),
            ("https://example.com.evil.com", "example.com", false),
        ];

        for (origin, rp_id, should_pass) in test_cases {
            let result = validate_rp_id_origin_binding(origin, rp_id).await;
            assert_eq!(result.is_ok(), should_pass, "Failed for origin: {}, rp_id: {}", origin, rp_id);
        }
    }
}
```

#### Cryptographic Verification Tests
```rust
#[cfg(test)]
mod crypto_verification_tests {
    #[tokio::test]
    async fn test_signature_algorithm_support() {
        let required_algorithms = vec![
            COSEAlgorithmIdentifier::ES256,  // -7 (Required by spec)
            COSEAlgorithmIdentifier::PS256,  // -37
            COSEAlgorithmIdentifier::RS256,  // -257
        ];

        for algorithm in required_algorithms {
            let test_credential = create_test_credential_with_algorithm(algorithm);
            let verification_result = verify_credential_signature(&test_credential).await;
            assert!(verification_result.is_ok(), "Algorithm {:?} should be supported", algorithm);
        }
    }

    #[tokio::test]
    async fn test_invalid_signature_rejection() {
        let credential = create_test_credential();
        let mut corrupted_credential = credential.clone();
        
        // Corrupt the signature
        corrupted_credential.signature[0] ^= 0xFF;
        
        let result = verify_credential_signature(&corrupted_credential).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::SignatureVerificationFailed);
    }

    #[tokio::test]
    async fn test_public_key_validation() {
        // Test: Invalid public key formats should be rejected
        let invalid_keys = vec![
            vec![],  // Empty key
            vec![0; 32],  // All zeros
            vec![0xFF; 32],  // All ones
            create_malformed_cose_key(),  // Malformed COSE key
        ];

        for invalid_key in invalid_keys {
            let result = validate_public_key(&invalid_key).await;
            assert!(result.is_err(), "Invalid key should be rejected: {:?}", invalid_key);
        }
    }
}
```

### 1.2 FIDO2 Compliance Tests (Priority 1)

#### Registration Flow Tests
```rust
#[cfg(test)]
mod registration_compliance_tests {
    #[tokio::test]
    async fn test_registration_options_generation() {
        let request = RegistrationBeginRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: UserVerificationRequirement::Preferred,
            authenticator_selection: Some(AuthenticatorSelectionCriteria::default()),
            attestation: AttestationConveyancePreference::Direct,
            extensions: None,
        };

        let response = generate_registration_options(&request).await.unwrap();
        
        // Verify required fields
        assert!(!response.challenge.is_empty());
        assert_eq!(response.rp.id, "example.com");
        assert!(!response.user.id.is_empty());
        assert_eq!(response.user.name, "test@example.com");
        assert!(!response.pub_key_cred_params.is_empty());
        
        // Verify algorithm support
        let es256_supported = response.pub_key_cred_params.iter()
            .any(|p| p.alg == COSEAlgorithmIdentifier::ES256);
        assert!(es256_supported, "ES256 algorithm must be supported");
        
        // Verify timeout is within acceptable range
        assert!(response.timeout >= 300_000 && response.timeout <= 600_000);
    }

    #[tokio::test]
    async fn test_attestation_verification_formats() {
        let attestation_formats = vec![
            "packed",
            "tpm",
            "android-key",
            "android-safetynet",
            "fido-u2f",
            "none",
        ];

        for format in attestation_formats {
            let test_attestation = create_test_attestation_object(format);
            let result = verify_attestation(&test_attestation).await;
            
            // Should either succeed or fail with format-specific error
            match result {
                Ok(_) => println!("Format {} verification succeeded", format),
                Err(e) => {
                    // Specific format errors are acceptable
                    assert_ne!(e, AttestationError::UnsupportedFormat);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_credential_exclusion() {
        // Setup: Register a credential
        let user = create_test_user().await;
        let credential = register_test_credential(&user).await.unwrap();

        // Test: Request new registration with exclusion list
        let request = RegistrationBeginRequest {
            username: user.username.clone(),
            // ... other fields
        };

        let options = generate_registration_options(&request).await.unwrap();
        
        // Verify the existing credential is in exclude list
        assert!(options.exclude_credentials.iter()
            .any(|c| c.id == credential.id));
    }
}
```

#### Authentication Flow Tests
```rust
#[cfg(test)]
mod authentication_compliance_tests {
    #[tokio::test]
    async fn test_authentication_options_generation() {
        // Setup: Register a credential first
        let user = create_test_user().await;
        let credential = register_test_credential(&user).await.unwrap();

        let request = AuthenticationBeginRequest {
            username: user.username.clone(),
            user_verification: UserVerificationRequirement::Preferred,
            extensions: None,
        };

        let response = generate_authentication_options(&request).await.unwrap();
        
        // Verify required fields
        assert!(!response.challenge.is_empty());
        assert_eq!(response.rp_id, "example.com");
        assert!(!response.allow_credentials.is_empty());
        
        // Verify the registered credential is in allow list
        assert!(response.allow_credentials.iter()
            .any(|c| c.id == credential.id));
    }

    #[tokio::test]
    async fn test_signature_counter_validation() {
        let credential = create_test_credential_with_counter(100).await;
        
        // Test: Valid counter increment
        let auth_response = create_test_auth_response_with_counter(&credential, 101);
        let result = verify_authentication(&auth_response).await;
        assert!(result.is_ok());

        // Test: Counter rollback should fail
        let auth_response_rollback = create_test_auth_response_with_counter(&credential, 99);
        let result = verify_authentication(&auth_response_rollback).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthenticationError::CounterRollback);
    }

    #[tokio::test]
    async fn test_user_verification_enforcement() {
        let test_cases = vec![
            (UserVerificationRequirement::Required, false, false),  // Should fail
            (UserVerificationRequirement::Required, true, true),    // Should pass
            (UserVerificationRequirement::Preferred, false, true),  // Should pass
            (UserVerificationRequirement::Preferred, true, true),   // Should pass
            (UserVerificationRequirement::Discouraged, false, true), // Should pass
            (UserVerificationRequirement::Discouraged, true, true),  // Should pass
        ];

        for (requirement, uv_performed, should_succeed) in test_cases {
            let auth_response = create_test_auth_response_with_uv(uv_performed);
            let result = verify_authentication_with_uv_requirement(&auth_response, requirement).await;
            
            assert_eq!(result.is_ok(), should_succeed, 
                "UV requirement: {:?}, performed: {}, should succeed: {}", 
                requirement, uv_performed, should_succeed);
        }
    }
}
```

### 1.3 Input Validation Tests (Priority 2)

```rust
#[cfg(test)]
mod input_validation_tests {
    #[tokio::test]
    async fn test_malformed_json_handling() {
        let malformed_payloads = vec![
            "",  // Empty
            "{",  // Incomplete
            "{'invalid': json}",  // Single quotes
            "{\"key\": undefined}",  // Invalid value
            &"x".repeat(1_000_000),  // Too large
        ];

        for payload in malformed_payloads {
            let result = parse_registration_request(payload).await;
            assert!(result.is_err(), "Should reject malformed JSON: {}", payload);
        }
    }

    #[tokio::test]
    async fn test_base64url_validation() {
        let invalid_base64_values = vec![
            "invalid+chars/=",  // Wrong encoding
            "too short",  // Not base64
            "",  // Empty
            "=====",  // Only padding
        ];

        for value in invalid_base64_values {
            let result = decode_base64url(value).await;
            assert!(result.is_err(), "Should reject invalid base64: {}", value);
        }
    }

    #[tokio::test]
    async fn test_size_limits() {
        // Test maximum sizes for various fields
        let oversized_username = "x".repeat(1000);
        let oversized_challenge = vec![0u8; 10000];
        let oversized_credential_id = vec![0u8; 5000];

        let result = validate_username(&oversized_username).await;
        assert!(result.is_err());

        let result = validate_challenge(&oversized_challenge).await;
        assert!(result.is_err());

        let result = validate_credential_id(&oversized_credential_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sql_injection_prevention() {
        let malicious_inputs = vec![
            "'; DROP TABLE users; --",
            "admin' OR '1'='1",
            "user@evil.com'; INSERT INTO users...",
            "<script>alert('xss')</script>@example.com",
        ];

        for input in malicious_inputs {
            // Attempt registration with malicious username
            let request = RegistrationBeginRequest {
                username: input.to_string(),
                display_name: "Test".to_string(),
                // ... other fields
            };

            let result = process_registration_begin(&request).await;
            
            // Should either sanitize or reject
            match result {
                Ok(response) => {
                    // Verify username was sanitized
                    assert!(!response.user.name.contains("'"));
                    assert!(!response.user.name.contains("<script>"));
                },
                Err(_) => {
                    // Rejection is also acceptable
                }
            }
        }
    }
}
```

### 1.4 Performance & Load Tests (Priority 3)

```rust
#[cfg(test)]
mod performance_tests {
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_registration_performance() {
        let start = std::time::Instant::now();
        
        // Test: Registration should complete within reasonable time
        let request = create_test_registration_request();
        let result = timeout(Duration::from_secs(5), 
            process_registration_begin(&request)).await;
        
        assert!(result.is_ok(), "Registration should complete within 5 seconds");
        
        let duration = start.elapsed();
        assert!(duration < Duration::from_millis(1000), 
            "Registration should complete within 1 second, took: {:?}", duration);
    }

    #[tokio::test]
    async fn test_concurrent_registrations() {
        let num_concurrent = 100;
        let mut handles = Vec::new();

        for i in 0..num_concurrent {
            let handle = tokio::spawn(async move {
                let request = create_test_registration_request_for_user(&format!("user{}@example.com", i));
                process_registration_begin(&request).await
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        
        // All should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_memory_usage() {
        use std::mem::size_of;
        
        // Test: Data structures should be reasonably sized
        assert!(size_of::<Credential>() < 1024, "Credential structure too large");
        assert!(size_of::<ChallengeState>() < 512, "ChallengeState structure too large");
        
        // Test: Memory leak detection
        let initial_memory = get_memory_usage();
        
        // Perform many operations
        for _ in 0..1000 {
            let _ = generate_challenge().await;
        }
        
        // Force garbage collection
        tokio::task::yield_now().await;
        
        let final_memory = get_memory_usage();
        let memory_increase = final_memory - initial_memory;
        
        assert!(memory_increase < 10 * 1024 * 1024, 
            "Memory usage increased too much: {} bytes", memory_increase);
    }
}
```

### 1.5 Integration Tests (Priority 2)

```rust
#[cfg(test)]
mod integration_tests {
    use reqwest::Client;

    #[tokio::test]
    async fn test_full_registration_flow() {
        let server = start_test_server().await;
        let client = Client::new();
        let base_url = server.base_url();

        // Step 1: Request registration options
        let begin_request = RegistrationBeginRequest {
            username: "integration@example.com".to_string(),
            display_name: "Integration Test".to_string(),
            user_verification: UserVerificationRequirement::Preferred,
            authenticator_selection: None,
            attestation: AttestationConveyancePreference::None,
            extensions: None,
        };

        let response = client
            .post(&format!("{}/webauthn/register/begin", base_url))
            .json(&begin_request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let options: RegistrationBeginResponse = response.json().await.unwrap();
        assert_eq!(options.status, "ok");

        // Step 2: Complete registration
        let complete_request = create_test_registration_complete_request(&options);
        
        let response = client
            .post(&format!("{}/webauthn/register/complete", base_url))
            .json(&complete_request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let result: RegistrationCompleteResponse = response.json().await.unwrap();
        assert_eq!(result.status, "ok");
        assert!(result.verified);
    }

    #[tokio::test]
    async fn test_full_authentication_flow() {
        let server = start_test_server().await;
        let client = Client::new();
        let base_url = server.base_url();

        // Prerequisites: Register a credential first
        let credential = register_test_credential_via_api(&client, &base_url).await;

        // Step 1: Request authentication options
        let begin_request = AuthenticationBeginRequest {
            username: credential.username.clone(),
            user_verification: UserVerificationRequirement::Preferred,
            extensions: None,
        };

        let response = client
            .post(&format!("{}/webauthn/authenticate/begin", base_url))
            .json(&begin_request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let options: AuthenticationBeginResponse = response.json().await.unwrap();
        assert_eq!(options.status, "ok");

        // Step 2: Complete authentication
        let complete_request = create_test_authentication_complete_request(&options, &credential);
        
        let response = client
            .post(&format!("{}/webauthn/authenticate/complete", base_url))
            .json(&complete_request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let result: AuthenticationCompleteResponse = response.json().await.unwrap();
        assert_eq!(result.status, "ok");
        assert!(result.verified);
    }

    #[tokio::test]
    async fn test_database_persistence() {
        let server = start_test_server_with_postgres().await;
        let client = Client::new();
        
        // Register credential
        let credential = register_test_credential_via_api(&client, &server.base_url()).await;
        
        // Restart server to test persistence
        server.stop().await;
        let new_server = start_test_server_with_same_db().await;
        
        // Try to authenticate with persisted credential
        let auth_result = authenticate_via_api(&client, &new_server.base_url(), &credential).await;
        assert!(auth_result.verified, "Credential should persist across server restarts");
    }
}
```

### 1.6 Error Handling Tests (Priority 2)

```rust
#[cfg(test)]
mod error_handling_tests {
    #[tokio::test]
    async fn test_detailed_error_responses() {
        let error_scenarios = vec![
            ("invalid_challenge", "Challenge not found or expired"),
            ("invalid_origin", "Origin not allowed"),
            ("credential_not_found", "Credential ID not recognized"),
            ("signature_verification_failed", "Invalid signature"),
            ("attestation_verification_failed", "Attestation could not be verified"),
        ];

        for (error_type, expected_message) in error_scenarios {
            let error_request = create_error_scenario_request(error_type);
            let response = process_request_expecting_error(&error_request).await;
            
            assert_eq!(response.status, "failed");
            assert!(response.error_message.contains(expected_message));
            assert!(!response.error_message.is_empty());
        }
    }

    #[tokio::test]
    async fn test_graceful_database_failure() {
        // Simulate database unavailability
        let server = start_server_with_broken_db().await;
        let client = Client::new();
        
        let request = create_test_registration_request();
        let response = client
            .post(&format!("{}/webauthn/register/begin", server.base_url()))
            .json(&request)
            .send()
            .await
            .unwrap();

        // Should return 503 Service Unavailable, not crash
        assert_eq!(response.status(), 503);
        
        let error_response: ErrorResponse = response.json().await.unwrap();
        assert_eq!(error_response.status, "failed");
        assert!(error_response.error_message.contains("Service temporarily unavailable"));
    }

    #[tokio::test]
    async fn test_rate_limiting_responses() {
        let server = start_test_server().await;
        let client = Client::new();
        
        // Exceed rate limit
        for _ in 0..100 {
            let _ = client
                .post(&format!("{}/webauthn/register/begin", server.base_url()))
                .json(&create_test_registration_request())
                .send()
                .await;
        }
        
        // Next request should be rate limited
        let response = client
            .post(&format!("{}/webauthn/register/begin", server.base_url()))
            .json(&create_test_registration_request())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 429);  // Too Many Requests
        
        let error_response: ErrorResponse = response.json().await.unwrap();
        assert!(error_response.error_message.contains("Rate limit exceeded"));
    }
}
```

## 2. Test Data & Fixtures

### 2.1 Test Vector Generation
```rust
pub struct TestVectorGenerator;

impl TestVectorGenerator {
    pub fn generate_valid_registration_request() -> RegistrationBeginRequest {
        RegistrationBeginRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: UserVerificationRequirement::Preferred,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                resident_key: ResidentKeyRequirement::Preferred,
                user_verification: UserVerificationRequirement::Preferred,
            }),
            attestation: AttestationConveyancePreference::Direct,
            extensions: None,
        }
    }

    pub fn generate_test_credentials() -> Vec<TestCredential> {
        vec![
            TestCredential::es256_credential(),
            TestCredential::rs256_credential(),
            TestCredential::eddsa_credential(),
            TestCredential::resident_key_credential(),
            TestCredential::platform_authenticator_credential(),
            TestCredential::roaming_authenticator_credential(),
        ]
    }

    pub fn generate_malicious_inputs() -> Vec<MaliciousInput> {
        vec![
            MaliciousInput::sql_injection("'; DROP TABLE users; --"),
            MaliciousInput::xss_payload("<script>alert('xss')</script>"),
            MaliciousInput::oversized_input(&"x".repeat(100000)),
            MaliciousInput::invalid_encoding("\xFF\xFE"),
            MaliciousInput::null_bytes("user\x00@example.com"),
        ]
    }
}
```

### 2.2 Mock Authenticator Implementation
```rust
pub struct MockAuthenticator {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    algorithm: COSEAlgorithmIdentifier,
    counter: AtomicU32,
    aaguid: Vec<u8>,
}

impl MockAuthenticator {
    pub async fn make_credential(&self, options: &PublicKeyCredentialCreationOptions) 
        -> Result<AuthenticatorAttestationResponse, AuthenticatorError> {
        
        // Simulate credential creation
        let credential_id = self.generate_credential_id();
        let client_data_json = self.create_client_data_json(
            &options.challenge, 
            "webauthn.create", 
            &options.rp.id
        );
        
        let attestation_object = self.create_attestation_object(
            &options.rp.id,
            &credential_id,
            &client_data_json
        )?;

        Ok(AuthenticatorAttestationResponse {
            credential_id,
            attestation_object,
            client_data_json,
            transports: vec!["usb".to_string(), "nfc".to_string()],
        })
    }

    pub async fn get_assertion(&self, options: &PublicKeyCredentialRequestOptions)
        -> Result<AuthenticatorAssertionResponse, AuthenticatorError> {
        
        // Find matching credential
        let credential_id = options.allow_credentials
            .first()
            .map(|c| c.id.clone())
            .ok_or(AuthenticatorError::NoCredentialsFound)?;

        let client_data_json = self.create_client_data_json(
            &options.challenge,
            "webauthn.get",
            &options.rp_id
        );

        let authenticator_data = self.create_authenticator_data(&options.rp_id, true, false);
        let signature = self.sign_assertion(&authenticator_data, &client_data_json)?;

        Ok(AuthenticatorAssertionResponse {
            credential_id,
            authenticator_data,
            signature,
            client_data_json,
            user_handle: Some(b"test-user".to_vec()),
        })
    }
}
```

## 3. Continuous Integration Test Strategy

### 3.1 Test Pipeline Stages
```yaml
# .github/workflows/test.yml
name: FIDO2 WebAuthn Tests

on: [push, pull_request]

jobs:
  security_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Tests
        run: cargo test security_tests -- --nocapture
        
  compliance_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run FIDO2 Compliance Tests
        run: cargo test compliance_tests -- --nocapture
        
  integration_tests:
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
      - name: Run Integration Tests
        run: cargo test integration_tests
        
  fuzz_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run Fuzz Tests
        run: |
          cargo fuzz run registration_fuzz -- -max_total_time=300
          cargo fuzz run authentication_fuzz -- -max_total_time=300
```

### 3.2 Test Coverage Requirements
- **Line Coverage**: Minimum 90%
- **Branch Coverage**: Minimum 85%
- **Security Critical Code**: 100% coverage required
- **Error Paths**: All error conditions must have test coverage

This comprehensive test planning strategy ensures thorough validation of all FIDO2/WebAuthn functionality, security requirements, and compliance standards.