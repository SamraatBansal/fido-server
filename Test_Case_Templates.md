# FIDO2/WebAuthn Test Case Templates & Implementation Guidance

## Test Case Categories & Templates

### 1. Unit Test Templates

#### 1.1 Challenge Generation Security Tests
```rust
#[cfg(test)]
mod challenge_security_tests {
    use super::*;
    use std::collections::HashSet;
    
    #[tokio::test]
    async fn test_challenge_entropy_requirements() {
        let mut challenge_gen = SecureChallenge::new();
        let challenge = challenge_gen.generate_challenge().unwrap();
        
        // Verify minimum length (32 bytes per WebAuthn spec)
        assert!(challenge.len() >= 32, "Challenge must be at least 32 bytes");
        
        // Verify not all zeros (basic entropy check)
        assert!(!challenge.iter().all(|&b| b == 0), "Challenge must have entropy");
    }
    
    #[tokio::test]
    async fn test_challenge_uniqueness() {
        let mut challenge_gen = SecureChallenge::new();
        let mut challenges = HashSet::new();
        
        // Generate 1000 challenges and verify uniqueness
        for _ in 0..1000 {
            let challenge = challenge_gen.generate_challenge().unwrap();
            let challenge_hex = hex::encode(&challenge);
            assert!(!challenges.contains(&challenge_hex), 
                   "Challenge collision detected: {}", challenge_hex);
            challenges.insert(challenge_hex);
        }
    }
    
    #[tokio::test]
    async fn test_challenge_expiration() {
        let challenge_store = InMemoryChallengeStore::new();
        let challenge = b"test_challenge_data".to_vec();
        
        // Store challenge with 1 second expiration
        challenge_store.store_challenge(&challenge, Duration::from_secs(1)).await.unwrap();
        
        // Verify challenge exists immediately
        assert!(challenge_store.validate_challenge(&challenge).await.unwrap());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Verify challenge is expired
        assert!(!challenge_store.validate_challenge(&challenge).await.unwrap());
    }
}
```

#### 1.2 Origin Validation Tests
```rust
#[cfg(test)]
mod origin_validation_tests {
    use super::*;
    
    #[test]
    fn test_valid_origin_validation() {
        let validator = OriginValidator::new(vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ]);
        
        // Valid origins should pass
        assert!(validator.validate_origin("https://example.com", "example.com").is_ok());
        assert!(validator.validate_origin("https://app.example.com", "example.com").is_ok());
    }
    
    #[test]
    fn test_invalid_origin_rejection() {
        let validator = OriginValidator::new(vec!["https://example.com".to_string()]);
        
        // Different domain should fail
        assert!(validator.validate_origin("https://evil.com", "example.com").is_err());
        
        // HTTP should fail (except localhost)
        assert!(validator.validate_origin("http://example.com", "example.com").is_err());
        
        // Subdomain attack should fail
        assert!(validator.validate_origin("https://evilexample.com", "example.com").is_err());
    }
    
    #[test]
    fn test_rp_id_origin_relationship() {
        let validator = OriginValidator::new(vec!["https://app.example.com".to_string()]);
        
        // RP ID must be registrable domain suffix
        assert!(validator.validate_origin("https://app.example.com", "example.com").is_ok());
        assert!(validator.validate_origin("https://app.example.com", "app.example.com").is_ok());
        
        // Invalid RP ID relationships should fail
        assert!(validator.validate_origin("https://app.example.com", "different.com").is_err());
        assert!(validator.validate_origin("https://app.example.com", "evil.example.com").is_err());
    }
}
```

### 2. Integration Test Templates

#### 2.1 Registration Flow Tests
```rust
#[cfg(test)]
mod registration_flow_tests {
    use super::*;
    use reqwest::Client;
    use serde_json::json;
    
    #[tokio::test]
    async fn test_complete_registration_flow() {
        let test_server = TestServer::start().await;
        let client = Client::new();
        
        // Step 1: Request registration options
        let options_response = client
            .post(&format!("{}/webauthn/register/begin", test_server.url()))
            .json(&json!({
                "username": "test@example.com",
                "displayName": "Test User"
            }))
            .send()
            .await
            .unwrap();
        
        assert_eq!(options_response.status(), 200);
        let options: RegistrationBeginResponse = options_response.json().await.unwrap();
        
        // Verify required fields present
        assert_eq!(options.status, "ok");
        assert!(!options.challenge.is_empty());
        assert_eq!(options.rp.id, "localhost");
        assert_eq!(options.user.name, "test@example.com");
        assert!(!options.pub_key_cred_params.is_empty());
        
        // Step 2: Simulate authenticator response
        let mock_credential = create_mock_credential_response(&options);
        
        // Step 3: Complete registration
        let complete_response = client
            .post(&format!("{}/webauthn/register/complete", test_server.url()))
            .json(&mock_credential)
            .send()
            .await
            .unwrap();
        
        assert_eq!(complete_response.status(), 200);
        let result: RegistrationCompleteResponse = complete_response.json().await.unwrap();
        assert_eq!(result.status, "ok");
        
        // Verify credential was stored
        let stored_creds = test_server.get_user_credentials("test@example.com").await.unwrap();
        assert_eq!(stored_creds.len(), 1);
    }
    
    #[tokio::test]
    async fn test_registration_failure_scenarios() {
        let test_server = TestServer::start().await;
        let client = Client::new();
        
        // Test invalid username
        let response = client
            .post(&format!("{}/webauthn/register/begin", test_server.url()))
            .json(&json!({
                "username": "", // Empty username
                "displayName": "Test User"
            }))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 400);
        
        // Test duplicate registration
        test_server.create_test_user("existing@example.com").await.unwrap();
        
        let response = client
            .post(&format!("{}/webauthn/register/begin", test_server.url()))
            .json(&json!({
                "username": "existing@example.com",
                "displayName": "Existing User"
            }))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 409); // Conflict
    }
}
```

#### 2.2 Authentication Flow Tests
```rust
#[cfg(test)]
mod authentication_flow_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_complete_authentication_flow() {
        let test_server = TestServer::start().await;
        let client = Client::new();
        
        // Prerequisite: Register a user and credential
        let (user, credential) = test_server.setup_test_user_with_credential().await.unwrap();
        
        // Step 1: Request authentication options
        let options_response = client
            .post(&format!("{}/webauthn/authenticate/begin", test_server.url()))
            .json(&json!({
                "username": user.username
            }))
            .send()
            .await
            .unwrap();
        
        assert_eq!(options_response.status(), 200);
        let options: AuthenticationBeginResponse = options_response.json().await.unwrap();
        
        // Verify required fields
        assert_eq!(options.status, "ok");
        assert!(!options.challenge.is_empty());
        assert_eq!(options.allow_credentials.len(), 1);
        assert_eq!(options.allow_credentials[0].id, credential.credential_id_b64);
        
        // Step 2: Simulate authenticator assertion
        let mock_assertion = create_mock_assertion_response(&options, &credential);
        
        // Step 3: Complete authentication
        let complete_response = client
            .post(&format!("{}/webauthn/authenticate/complete", test_server.url()))
            .json(&mock_assertion)
            .send()
            .await
            .unwrap();
        
        assert_eq!(complete_response.status(), 200);
        let result: AuthenticationCompleteResponse = complete_response.json().await.unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.user.name, user.username);
    }
    
    #[tokio::test]
    async fn test_authentication_security_failures() {
        let test_server = TestServer::start().await;
        let client = Client::new();
        let (user, credential) = test_server.setup_test_user_with_credential().await.unwrap();
        
        // Get valid options
        let options = test_server.get_authentication_options(&user.username).await.unwrap();
        
        // Test 1: Invalid signature
        let mut invalid_assertion = create_mock_assertion_response(&options, &credential);
        invalid_assertion["response"]["signature"] = json!("invalid_signature_data");
        
        let response = client
            .post(&format!("{}/webauthn/authenticate/complete", test_server.url()))
            .json(&invalid_assertion)
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 401); // Unauthorized
        
        // Test 2: Challenge reuse
        let valid_assertion = create_mock_assertion_response(&options, &credential);
        
        // First use should succeed
        let response1 = client
            .post(&format!("{}/webauthn/authenticate/complete", test_server.url()))
            .json(&valid_assertion)
            .send()
            .await
            .unwrap();
        assert_eq!(response1.status(), 200);
        
        // Second use should fail (replay attack)
        let response2 = client
            .post(&format!("{}/webauthn/authenticate/complete", test_server.url()))
            .json(&valid_assertion)
            .send()
            .await
            .unwrap();
        assert_eq!(response2.status(), 401);
    }
}
```

### 3. FIDO Alliance Conformance Tests

#### 3.1 Signature Algorithm Conformance
```rust
#[cfg(test)]
mod fido_conformance_signature_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ecdsa_p256_signature_verification() {
        let test_server = TestServer::start().await;
        
        // Create test credential with ECDSA P-256 algorithm (-7)
        let test_vector = TestVectorLoader::load("ecdsa_p256_registration.json").unwrap();
        
        // Test registration with ECDSA P-256
        let registration_result = test_server
            .execute_registration_test_vector(&test_vector)
            .await
            .unwrap();
        
        assert!(registration_result.success);
        
        // Verify algorithm is correctly stored
        let stored_credential = test_server
            .get_credential_by_id(&test_vector.credential_id)
            .await
            .unwrap();
        
        let public_key = parse_cose_public_key(&stored_credential.public_key).unwrap();
        assert_eq!(public_key.algorithm(), -7); // ES256
        
        // Test authentication with stored credential
        let auth_test_vector = TestVectorLoader::load("ecdsa_p256_authentication.json").unwrap();
        let auth_result = test_server
            .execute_authentication_test_vector(&auth_test_vector)
            .await
            .unwrap();
        
        assert!(auth_result.success);
    }
    
    #[tokio::test]
    async fn test_rsa_signature_verification() {
        let test_server = TestServer::start().await;
        
        // Test RSA PKCS#1 SHA-256 algorithm (-257)
        let test_vector = TestVectorLoader::load("rsa_pkcs1_registration.json").unwrap();
        
        let registration_result = test_server
            .execute_registration_test_vector(&test_vector)
            .await
            .unwrap();
        
        assert!(registration_result.success);
        
        // Verify RSA key parameters
        let stored_credential = test_server
            .get_credential_by_id(&test_vector.credential_id)
            .await
            .unwrap();
        
        let public_key = parse_cose_public_key(&stored_credential.public_key).unwrap();
        assert_eq!(public_key.algorithm(), -257); // RS256
        
        // Verify modulus and exponent are present
        assert!(public_key.get_rsa_modulus().is_some());
        assert!(public_key.get_rsa_exponent().is_some());
    }
}
```

#### 3.2 Attestation Format Conformance
```rust
#[cfg(test)]
mod attestation_conformance_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_none_attestation_format() {
        let test_server = TestServer::start().await;
        
        let test_vector = TestVectorLoader::load("none_attestation.json").unwrap();
        let result = test_server.execute_registration_test_vector(&test_vector).await.unwrap();
        
        assert!(result.success);
        
        // Verify attestation type is stored correctly
        let credential = test_server.get_credential_by_id(&test_vector.credential_id).await.unwrap();
        assert_eq!(credential.attestation_type, "none");
    }
    
    #[tokio::test]
    async fn test_self_attestation_format() {
        let test_server = TestServer::start().await;
        
        let test_vector = TestVectorLoader::load("self_attestation.json").unwrap();
        let result = test_server.execute_registration_test_vector(&test_vector).await.unwrap();
        
        assert!(result.success);
        
        let credential = test_server.get_credential_by_id(&test_vector.credential_id).await.unwrap();
        assert_eq!(credential.attestation_type, "self");
    }
    
    #[tokio::test]
    async fn test_basic_attestation_format() {
        let test_server = TestServer::start().await;
        
        let test_vector = TestVectorLoader::load("basic_attestation.json").unwrap();
        let result = test_server.execute_registration_test_vector(&test_vector).await.unwrap();
        
        assert!(result.success);
        
        let credential = test_server.get_credential_by_id(&test_vector.credential_id).await.unwrap();
        assert_eq!(credential.attestation_type, "basic");
        
        // Verify attestation certificate chain was validated
        // Implementation would check certificate validation logs
    }
}
```

### 4. Security Test Templates

#### 4.1 Replay Attack Prevention Tests
```rust
#[cfg(test)]
mod replay_attack_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_challenge_replay_prevention() {
        let test_server = TestServer::start().await;
        let (user, credential) = test_server.setup_test_user_with_credential().await.unwrap();
        
        // Get authentication options
        let options = test_server.get_authentication_options(&user.username).await.unwrap();
        let assertion = create_mock_assertion_response(&options, &credential);
        
        // First authentication should succeed
        let result1 = test_server.complete_authentication(&assertion).await.unwrap();
        assert!(result1.success);
        
        // Replay same assertion should fail
        let result2 = test_server.complete_authentication(&assertion).await;
        assert!(result2.is_err());
        assert!(matches!(result2.unwrap_err(), AuthenticationError::ChallengeReuse));
    }
    
    #[tokio::test]
    async fn test_signature_counter_validation() {
        let test_server = TestServer::start().await;
        let (user, credential) = test_server.setup_test_user_with_credential().await.unwrap();
        
        // Perform successful authentication to increment counter
        let auth1_result = test_server.authenticate_user(&user.username).await.unwrap();
        assert!(auth1_result.success);
        
        // Get current counter value
        let credential_after = test_server.get_credential_by_id(&credential.id).await.unwrap();
        let current_counter = credential_after.sign_count;
        
        // Create assertion with lower counter (simulating replay)
        let options = test_server.get_authentication_options(&user.username).await.unwrap();
        let mut assertion = create_mock_assertion_response(&options, &credential);
        
        // Manually set lower counter in authenticator data
        set_authenticator_data_counter(&mut assertion, current_counter - 1);
        
        // Authentication should fail due to counter rollback
        let result = test_server.complete_authentication(&assertion).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthenticationError::CounterRollback));
    }
}
```

#### 4.2 Input Validation Security Tests
```rust
#[cfg(test)]
mod input_validation_security_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_malformed_registration_request_handling() {
        let test_server = TestServer::start().await;
        
        // Test cases for malformed input
        let malformed_inputs = vec![
            json!({}), // Empty object
            json!({"username": ""}), // Empty username
            json!({"username": "a".repeat(1000)}), // Oversized username
            json!({"username": "test", "displayName": ""}), // Empty display name
            json!({"username": "test\x00user"}), // Null byte injection
            json!({"username": 12345}), // Wrong type
        ];
        
        for input in malformed_inputs {
            let response = test_server.post_registration_begin(&input).await;
            assert!(response.status().is_client_error(), 
                   "Should reject malformed input: {:?}", input);
        }
    }
    
    #[tokio::test]
    async fn test_oversized_credential_handling() {
        let test_server = TestServer::start().await;
        
        // Create oversized credential data (> 1023 bytes per spec)
        let oversized_credential_id = vec![0u8; 2000];
        let oversized_public_key = vec![0u8; 10000];
        
        let registration_complete = json!({
            "id": base64::encode_config(&oversized_credential_id, base64::URL_SAFE_NO_PAD),
            "rawId": base64::encode_config(&oversized_credential_id, base64::URL_SAFE_NO_PAD),
            "response": {
                "clientDataJSON": "valid_client_data",
                "attestationObject": create_attestation_with_oversized_key(&oversized_public_key)
            },
            "type": "public-key"
        });
        
        let response = test_server.post_registration_complete(&registration_complete).await;
        assert_eq!(response.status(), 400); // Bad Request
    }
    
    #[tokio::test]
    async fn test_injection_attack_prevention() {
        let test_server = TestServer::start().await;
        
        // Test SQL injection attempts
        let injection_attempts = vec![
            "'; DROP TABLE users; --",
            "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",
            "' OR '1'='1",
            "'; UPDATE users SET password='hacked'; --"
        ];
        
        for injection in injection_attempts {
            let request = json!({
                "username": injection,
                "displayName": "Test User"
            });
            
            let response = test_server.post_registration_begin(&request).await;
            
            // Should either reject as invalid format or handle safely
            if response.status().is_success() {
                // If accepted, verify no SQL injection occurred
                let users = test_server.get_all_users().await.unwrap();
                assert!(!users.is_empty()); // Table should still exist
                
                // Verify no unauthorized changes
                for user in users {
                    assert_ne!(user.password, Some("hacked".to_string()));
                }
            }
        }
    }
}
```

### 5. Performance & Load Testing Templates

#### 5.1 Concurrent Request Handling
```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use tokio::time::{Duration, Instant};
    use futures::future::join_all;
    
    #[tokio::test]
    async fn test_concurrent_registration_requests() {
        let test_server = TestServer::start().await;
        let concurrent_requests = 100;
        
        let start_time = Instant::now();
        
        // Create concurrent registration requests
        let tasks: Vec<_> = (0..concurrent_requests)
            .map(|i| {
                let server = test_server.clone();
                tokio::spawn(async move {
                    let username = format!("user{}@example.com", i);
                    server.register_user(&username, "Test User").await
                })
            })
            .collect();
        
        let results = join_all(tasks).await;
        let duration = start_time.elapsed();
        
        // Verify all requests completed successfully
        let successful_registrations = results
            .into_iter()
            .filter_map(|r| r.ok())
            .filter(|r| r.is_ok())
            .count();
        
        assert_eq!(successful_registrations, concurrent_requests);
        
        // Performance assertion (adjust based on requirements)
        assert!(duration < Duration::from_secs(10), 
               "100 concurrent registrations took {:?}", duration);
    }
    
    #[tokio::test]
    async fn test_authentication_performance() {
        let test_server = TestServer::start().await;
        
        // Setup test users
        let num_users = 50;
        let mut users = Vec::new();
        
        for i in 0..num_users {
            let username = format!("perfuser{}@example.com", i);
            let (user, _) = test_server.setup_test_user_with_credential_named(&username).await.unwrap();
            users.push(user);
        }
        
        // Perform concurrent authentications
        let start_time = Instant::now();
        
        let auth_tasks: Vec<_> = users
            .into_iter()
            .map(|user| {
                let server = test_server.clone();
                tokio::spawn(async move {
                    server.authenticate_user(&user.username).await
                })
            })
            .collect();
        
        let auth_results = join_all(auth_tasks).await;
        let duration = start_time.elapsed();
        
        // Verify all authentications succeeded
        let successful_auths = auth_results
            .into_iter()
            .filter_map(|r| r.ok())
            .filter(|r| r.is_ok())
            .count();
        
        assert_eq!(successful_auths, num_users);
        
        // Performance requirement: < 5 seconds for 50 concurrent auths
        assert!(duration < Duration::from_secs(5),
               "50 concurrent authentications took {:?}", duration);
    }
}
```

### 6. Test Utilities & Mocking Framework

#### 6.1 Mock Authenticator Implementation
```rust
pub struct MockAuthenticator {
    private_key: PrivateKey,
    public_key: PublicKey,
    aaguid: [u8; 16],
    counter: AtomicU32,
}

impl MockAuthenticator {
    pub fn new_ecdsa_p256() -> Self {
        let private_key = PrivateKey::generate_ecdsa_p256();
        let public_key = private_key.public_key();
        
        Self {
            private_key,
            public_key,
            aaguid: [0u8; 16], // Null AAGUID for testing
            counter: AtomicU32::new(1),
        }
    }
    
    pub fn create_credential_response(
        &self,
        options: &RegistrationBeginResponse,
        origin: &str,
    ) -> serde_json::Value {
        let client_data = ClientData {
            type_: "webauthn.create".to_string(),
            challenge: options.challenge.clone(),
            origin: origin.to_string(),
        };
        
        let client_data_json = serde_json::to_string(&client_data).unwrap();
        let client_data_hash = sha256(client_data_json.as_bytes());
        
        let credential_id = generate_random_bytes(32);
        let auth_data = self.create_authenticator_data(
            &options.rp.id,
            &credential_id,
            true, // include_credential
        );
        
        let attestation_object = self.create_attestation_object(&auth_data, &client_data_hash);
        
        json!({
            "id": base64::encode_config(&credential_id, base64::URL_SAFE_NO_PAD),
            "rawId": base64::encode_config(&credential_id, base64::URL_SAFE_NO_PAD),
            "response": {
                "clientDataJSON": base64::encode_config(&client_data_json, base64::URL_SAFE_NO_PAD),
                "attestationObject": base64::encode_config(&attestation_object, base64::URL_SAFE_NO_PAD)
            },
            "type": "public-key"
        })
    }
    
    pub fn create_assertion_response(
        &self,
        options: &AuthenticationBeginResponse,
        credential_id: &[u8],
        origin: &str,
    ) -> serde_json::Value {
        let client_data = ClientData {
            type_: "webauthn.get".to_string(),
            challenge: options.challenge.clone(),
            origin: origin.to_string(),
        };
        
        let client_data_json = serde_json::to_string(&client_data).unwrap();
        let client_data_hash = sha256(client_data_json.as_bytes());
        
        let auth_data = self.create_authenticator_data(&options.rp_id, credential_id, false);
        let signature = self.sign_assertion(&auth_data, &client_data_hash);
        
        json!({
            "id": base64::encode_config(credential_id, base64::URL_SAFE_NO_PAD),
            "rawId": base64::encode_config(credential_id, base64::URL_SAFE_NO_PAD),
            "response": {
                "clientDataJSON": base64::encode_config(&client_data_json, base64::URL_SAFE_NO_PAD),
                "authenticatorData": base64::encode_config(&auth_data, base64::URL_SAFE_NO_PAD),
                "signature": base64::encode_config(&signature, base64::URL_SAFE_NO_PAD),
                "userHandle": base64::encode_config(b"test_user_handle", base64::URL_SAFE_NO_PAD)
            },
            "type": "public-key"
        })
    }
    
    fn create_authenticator_data(&self, rp_id: &str, credential_id: &[u8], include_credential: bool) -> Vec<u8> {
        let mut auth_data = Vec::new();
        
        // RP ID hash (32 bytes)
        auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
        
        // Flags (1 byte)
        let mut flags = 0x01; // User Present
        if include_credential {
            flags |= 0x40; // Attested credential data included
        }
        auth_data.push(flags);
        
        // Signature counter (4 bytes, big endian)
        let counter = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        
        if include_credential {
            // AAGUID (16 bytes)
            auth_data.extend_from_slice(&self.aaguid);
            
            // Credential ID length (2 bytes, big endian)
            auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
            
            // Credential ID
            auth_data.extend_from_slice(credential_id);
            
            // Public key (COSE format)
            let cose_key = self.public_key.to_cose_bytes();
            auth_data.extend_from_slice(&cose_key);
        }
        
        auth_data
    }
    
    fn sign_assertion(&self, auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(auth_data);
        signed_data.extend_from_slice(client_data_hash);
        
        self.private_key.sign(&signed_data)
    }
}
```

#### 6.2 Test Data Factory
```rust
pub struct TestDataFactory;

impl TestDataFactory {
    pub fn create_test_user(username: &str) -> CreateUserRequest {
        CreateUserRequest {
            username: username.to_string(),
            display_name: format!("Test User ({})", username),
            user_handle: generate_random_bytes(32),
        }
    }
    
    pub fn create_fido_test_vectors() -> Vec<TestVector> {
        vec![
            // ECDSA P-256 Registration
            TestVector {
                name: "ECDSA P-256 Registration".to_string(),
                description: "Test registration with ECDSA P-256 algorithm".to_string(),
                test_type: TestType::Registration,
                algorithm: Algorithm::ES256,
                attestation_type: AttestationType::None,
                expected_result: TestResult::Success,
                test_data: load_test_data("ecdsa_p256_registration.json"),
            },
            
            // RSA Registration
            TestVector {
                name: "RSA PKCS#1 Registration".to_string(),
                description: "Test registration with RSA PKCS#1 SHA-256".to_string(),
                test_type: TestType::Registration,
                algorithm: Algorithm::RS256,
                attestation_type: AttestationType::None,
                expected_result: TestResult::Success,
                test_data: load_test_data("rsa_pkcs1_registration.json"),
            },
            
            // Invalid Signature Test
            TestVector {
                name: "Invalid Signature Rejection".to_string(),
                description: "Test that invalid signatures are properly rejected".to_string(),
                test_type: TestType::Authentication,
                algorithm: Algorithm::ES256,
                attestation_type: AttestationType::None,
                expected_result: TestResult::Failure("Invalid signature".to_string()),
                test_data: load_test_data("invalid_signature_auth.json"),
            },
        ]
    }
}
```

This comprehensive test template collection provides:

1. **Structured Test Categories**: Unit, integration, conformance, and security tests
2. **Security-Focused Testing**: Emphasis on attack prevention and vulnerability testing
3. **FIDO Alliance Compliance**: Specific test cases for specification conformance
4. **Mock Framework**: Realistic authenticator simulation for testing
5. **Performance Testing**: Load and concurrency testing templates
6. **Comprehensive Coverage**: All major WebAuthn flows and edge cases

Each test template includes detailed assertions and follows security-first testing principles, ensuring that the implementation meets both functional and security requirements.