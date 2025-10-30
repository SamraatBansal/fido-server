# FIDO2/WebAuthn Server Test Specification

## Overview

This document provides a comprehensive test specification for the FIDO2/WebAuthn Relying Party Server implementation. It follows a test-driven development approach with detailed test cases for all security requirements, API endpoints, and compliance points.

## 1. Test Strategy

### 1.1 Test Pyramid

```
    /\
   /  \  E2E Tests (5%)
  /____\
 /      \
/________\ Integration Tests (25%)
/__________\
/____________\ Unit Tests (70%)
```

### 1.2 Test Categories

#### Unit Tests (70%)
- Service layer business logic
- Repository data access
- Utility functions
- Error handling
- Cryptographic operations

#### Integration Tests (25%)
- API endpoint contracts
- Database operations
- WebAuthn flow integration
- Security middleware

#### End-to-End Tests (5%)
- Complete user flows
- Cross-browser compatibility
- Performance under load
- Security attack simulations

## 2. Unit Test Specifications

### 2.1 WebAuthn Service Tests

#### Test Suite: WebAuthnServiceRegistration

```rust
#[cfg(test)]
mod registration_tests {
    use super::*;
    use mockall::predicate::*;
    
    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        // Given
        let username = "test@example.com";
        let display_name = "Test User";
        let user_verification = UserVerificationPolicy::Required;
        
        // When
        let result = webauthn_service
            .generate_registration_challenge(username, display_name, user_verification)
            .await;
        
        // Then
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.user.name, username);
        assert_eq!(challenge.user.display_name, display_name);
        assert!(challenge.timeout > 0);
    }
    
    #[tokio::test]
    async fn test_generate_registration_challenge_invalid_username() {
        // Given
        let username = ""; // Invalid empty username
        
        // When
        let result = webauthn_service
            .generate_registration_challenge(username, "Test User", UserVerificationPolicy::Required)
            .await;
        
        // Then
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidUsername));
    }
    
    #[tokio::test]
    async fn test_verify_registration_attestation_success() {
        // Given
        let challenge = create_test_challenge();
        let attestation = create_valid_attestation_response();
        
        // When
        let result = webauthn_service
            .verify_registration_attestation(challenge, attestation)
            .await;
        
        // Then
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert!(!credential.credential_id.is_empty());
        assert!(!credential.public_key.is_empty());
    }
    
    #[tokio::test]
    async fn test_verify_registration_attestation_invalid_signature() {
        // Given
        let challenge = create_test_challenge();
        let mut attestation = create_valid_attestation_response();
        attestation.response.signature = "invalid_signature".to_string();
        
        // When
        let result = webauthn_service
            .verify_registration_attestation(challenge, attestation)
            .await;
        
        // Then
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidSignature));
    }
    
    #[tokio::test]
    async fn test_verify_registration_attestation_expired_challenge() {
        // Given
        let mut challenge = create_test_challenge();
        challenge.expires_at = Utc::now() - Duration::minutes(1); // Expired
        let attestation = create_valid_attestation_response();
        
        // When
        let result = webauthn_service
            .verify_registration_attestation(challenge, attestation)
            .await;
        
        // Then
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::ChallengeExpired));
    }
}
```

#### Test Suite: WebAuthnServiceAuthentication

```rust
#[cfg(test)]
mod authentication_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_generate_authentication_challenge_success() {
        // Given
        let username = "test@example.com";
        let user_verification = UserVerificationPolicy::Preferred;
        let user_credentials = vec![create_test_credential()];
        
        // Mock repository to return user credentials
        user_repository
            .expect_get_credentials_by_username()
            .with(eq(username))
            .returning(move |_| Ok(user_credentials.clone()));
        
        // When
        let result = webauthn_service
            .generate_authentication_challenge(username, user_verification)
            .await;
        
        // Then
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert!(!challenge.challenge.is_empty());
        assert!(!challenge.allow_credentials.is_empty());
        assert_eq!(challenge.allow_credentials.len(), 1);
    }
    
    #[tokio::test]
    async fn test_generate_authentication_challenge_user_not_found() {
        // Given
        let username = "nonexistent@example.com";
        
        // Mock repository to return empty credentials
        user_repository
            .expect_get_credentials_by_username()
            .with(eq(username))
            .returning(|_| Ok(vec![]));
        
        // When
        let result = webauthn_service
            .generate_authentication_challenge(username, UserVerificationPolicy::Required)
            .await;
        
        // Then
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::UserNotFound));
    }
    
    #[tokio::test]
    async fn test_verify_authentication_assertion_success() {
        // Given
        let challenge = create_test_authentication_challenge();
        let assertion = create_valid_assertion_response();
        let stored_credential = create_test_credential();
        
        // Mock repository
        credential_repository
            .expect_get_by_credential_id()
            .with(eq(assertion.id))
            .returning(move |_| Ok(stored_credential.clone()));
        
        // When
        let result = webauthn_service
            .verify_authentication_assertion(challenge, assertion)
            .await;
        
        // Then
        assert!(result.is_ok());
        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert!(auth_result.user_id.is_some());
    }
    
    #[tokio::test]
    async fn test_verify_authentication_assertion_invalid_counter() {
        // Given
        let challenge = create_test_authentication_challenge();
        let assertion = create_valid_assertion_response();
        let mut stored_credential = create_test_credential();
        stored_credential.sign_count = 100; // Higher than assertion
        
        // Mock repository
        credential_repository
            .expect_get_by_credential_id()
            .with(eq(assertion.id))
            .returning(move |_| Ok(stored_credential.clone()));
        
        // When
        let result = webauthn_service
            .verify_authentication_assertion(challenge, assertion)
            .await;
        
        // Then
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebAuthnError::InvalidSignCounter));
    }
}
```

### 2.2 Repository Layer Tests

#### Test Suite: CredentialRepository

```rust
#[cfg(test)]
mod credential_repository_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_credential_success() {
        // Given
        let credential = create_test_credential();
        
        // When
        let result = credential_repository.create(&credential).await;
        
        // Then
        assert!(result.is_ok());
        
        // Verify credential was stored
        let stored = credential_repository
            .get_by_credential_id(&credential.credential_id)
            .await
            .unwrap();
        assert_eq!(stored.credential_id, credential.credential_id);
        assert_eq!(stored.user_id, credential.user_id);
    }
    
    #[tokio::test]
    async fn test_create_credential_duplicate_id() {
        // Given
        let credential = create_test_credential();
        
        // Create first credential
        credential_repository.create(&credential).await.unwrap();
        
        // When - try to create duplicate
        let result = credential_repository.create(&credential).await;
        
        // Then
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RepositoryError::DuplicateKey));
    }
    
    #[tokio::test]
    async fn test_get_credentials_by_user_id_success() {
        // Given
        let user_id = Uuid::new_v4();
        let credentials = vec![
            create_test_credential_with_user_id(user_id),
            create_test_credential_with_user_id(user_id),
        ];
        
        for cred in &credentials {
            credential_repository.create(cred).await.unwrap();
        }
        
        // When
        let result = credential_repository
            .get_by_user_id(&user_id)
            .await;
        
        // Then
        assert!(result.is_ok());
        let stored_creds = result.unwrap();
        assert_eq!(stored_creds.len(), 2);
    }
    
    #[tokio::test]
    async fn test_update_sign_counter_success() {
        // Given
        let credential = create_test_credential();
        credential_repository.create(&credential).await.unwrap();
        let new_counter = 42;
        
        // When
        let result = credential_repository
            .update_sign_counter(&credential.credential_id, new_counter)
            .await;
        
        // Then
        assert!(result.is_ok());
        
        let updated = credential_repository
            .get_by_credential_id(&credential.credential_id)
            .await
            .unwrap();
        assert_eq!(updated.sign_count, new_counter);
    }
}
```

### 2.3 Utility Function Tests

#### Test Suite: CryptoUtils

```rust
#[cfg(test)]
mod crypto_utils_tests {
    use super::*;
    
    #[test]
    fn test_generate_challenge_entropy() {
        // When
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        // Then
        assert_ne!(challenge1, challenge2);
        assert_eq!(challenge1.len(), 32); // 256 bits = 32 bytes
        assert_eq!(challenge2.len(), 32);
    }
    
    #[test]
    fn test_base64url_encoding_roundtrip() {
        // Given
        let data = b"test data for encoding";
        
        // When
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        
        // Then
        assert_eq!(decoded, data);
    }
    
    #[test]
    fn test_base64url_decode_invalid_input() {
        // Given
        let invalid_input = "invalid!base64url";
        
        // When
        let result = base64url_decode(invalid_input);
        
        // Then
        assert!(result.is_err());
    }
    
    #[test]
    fn test_verify_signature_es256_success() {
        // Given
        let key_pair = generate_es256_key_pair();
        let data = b"test message";
        let signature = sign_es256(&key_pair.private_key, data).unwrap();
        
        // When
        let result = verify_es256_signature(&key_pair.public_key, data, &signature);
        
        // Then
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_verify_signature_es256_invalid() {
        // Given
        let key_pair = generate_es256_key_pair();
        let data = b"test message";
        let wrong_data = b"wrong message";
        let signature = sign_es256(&key_pair.private_key, wrong_data).unwrap();
        
        // When
        let result = verify_es256_signature(&key_pair.public_key, data, &signature);
        
        // Then
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
```

## 3. Integration Test Specifications

### 3.1 API Endpoint Tests

#### Test Suite: RegistrationEndpoints

```rust
#[cfg(test)]
mod registration_integration_tests {
    use super::*;
    use actix_web::{test, App};
    
    #[actix_web::test]
    async fn test_register_begin_success() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let req_body = RegistrationBeginRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: "required".to_string(),
            attestation: "direct".to_string(),
        };
        
        // When
        let req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(&req_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Then
        assert_eq!(resp.status(), 200);
        
        let response: RegistrationBeginResponse = test::read_body_json(resp).await;
        assert!(!response.challenge.is_empty());
        assert_eq!(response.user.name, "test@example.com");
        assert_eq!(response.user.display_name, "Test User");
        assert!(response.timeout > 0);
    }
    
    #[actix_web::test]
    async fn test_register_begin_invalid_request() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let req_body = serde_json::json!({
            "username": "", // Invalid empty username
            "displayName": "Test User"
        });
        
        // When
        let req = test::TestRequest::post()
            .uri("/webauthn/register/begin")
            .set_json(&req_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Then
        assert_eq!(resp.status(), 400);
    }
    
    #[actix_web::test]
    async fn test_register_finish_success() {
        // Given
        let app = test::init_service(create_test_app()).await;
        
        // First, begin registration
        let begin_req = RegistrationBeginRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: "required".to_string(),
            attestation: "direct".to_string(),
        };
        
        let begin_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/register/begin")
                .set_json(&begin_req)
                .to_request()
        ).await;
        
        let begin_response: RegistrationBeginResponse = test::read_body_json(begin_resp).await;
        
        // Create attestation response
        let attestation = create_test_attestation_response(&begin_response.challenge);
        
        let finish_req = RegistrationFinishRequest {
            credential: attestation,
            user: User {
                id: begin_response.user.id,
                name: begin_response.user.name,
            },
        };
        
        // When
        let finish_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/register/finish")
                .set_json(&finish_req)
                .to_request()
        ).await;
        
        // Then
        assert_eq!(finish_resp.status(), 200);
        
        let response: RegistrationFinishResponse = test::read_body_json(finish_resp).await;
        assert_eq!(response.status, "ok");
        assert!(!response.credential_id.is_empty());
    }
    
    #[actix_web::test]
    async fn test_register_finish_invalid_attestation() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let req_body = serde_json::json!({
            "credential": {
                "id": "invalid_credential_id",
                "type": "public-key",
                "response": {
                    "attestationObject": "invalid_attestation",
                    "clientDataJSON": "invalid_client_data"
                }
            }
        });
        
        // When
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/register/finish")
                .set_json(&req_body)
                .to_request()
        ).await;
        
        // Then
        assert_eq!(resp.status(), 422);
    }
}
```

#### Test Suite: AuthenticationEndpoints

```rust
#[cfg(test)]
mod authentication_integration_tests {
    use super::*;
    
    #[actix_web::test]
    async fn test_authenticate_begin_success() {
        // Given
        let app = test::init_service(create_test_app()).await;
        
        // First, register a user with credentials
        setup_test_user_with_credentials(&app).await;
        
        let req_body = AuthenticationBeginRequest {
            username: "test@example.com".to_string(),
            user_verification: "required".to_string(),
        };
        
        // When
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/begin")
                .set_json(&req_body)
                .to_request()
        ).await;
        
        // Then
        assert_eq!(resp.status(), 200);
        
        let response: AuthenticationBeginResponse = test::read_body_json(resp).await;
        assert!(!response.challenge.is_empty());
        assert!(!response.allow_credentials.is_empty());
        assert_eq!(response.user_verification, "required");
    }
    
    #[actix_web::test]
    async fn test_authenticate_begin_user_not_found() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let req_body = AuthenticationBeginRequest {
            username: "nonexistent@example.com".to_string(),
            user_verification: "required".to_string(),
        };
        
        // When
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/begin")
                .set_json(&req_body)
                .to_request()
        ).await;
        
        // Then
        assert_eq!(resp.status(), 404);
    }
    
    #[actix_web::test]
    async fn test_authenticate_finish_success() {
        // Given
        let app = test::init_service(create_test_app()).await;
        
        // Setup user and begin authentication
        let (user, challenge) = setup_authentication_flow(&app).await;
        
        // Create assertion response
        let assertion = create_test_assertion_response(&challenge, &user.credentials[0]);
        
        let req_body = AuthenticationFinishRequest {
            credential: assertion,
        };
        
        // When
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/finish")
                .set_json(&req_body)
                .to_request()
        ).await;
        
        // Then
        assert_eq!(resp.status(), 200);
        
        let response: AuthenticationFinishResponse = test::read_body_json(resp).await;
        assert_eq!(response.status, "ok");
        assert!(!response.user.id.is_empty());
        assert!(response.sign_count >= 0);
    }
}
```

### 3.2 Database Integration Tests

```rust
#[cfg(test)]
mod database_integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_user_crud_operations() {
        // Given
        let pool = create_test_database_pool().await;
        let user_repo = UserRepository::new(pool.clone());
        
        let user = User {
            id: Uuid::new_v4(),
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            is_active: true,
        };
        
        // When - Create
        let create_result = user_repo.create(&user).await;
        assert!(create_result.is_ok());
        
        // Then - Read
        let retrieved = user_repo.get_by_id(&user.id).await.unwrap();
        assert_eq!(retrieved.username, user.username);
        assert_eq!(retrieved.display_name, user.display_name);
        
        // When - Update
        let mut updated_user = user.clone();
        updated_user.display_name = "Updated Name".to_string();
        let update_result = user_repo.update(&updated_user).await;
        assert!(update_result.is_ok());
        
        // Then - Verify update
        let updated = user_repo.get_by_id(&user.id).await.unwrap();
        assert_eq!(updated.display_name, "Updated Name");
        
        // When - Delete
        let delete_result = user_repo.delete(&user.id).await;
        assert!(delete_result.is_ok());
        
        // Then - Verify deletion
        let deleted = user_repo.get_by_id(&user.id).await;
        assert!(deleted.is_err());
    }
    
    #[tokio::test]
    async fn test_credential_user_cascade_delete() {
        // Given
        let pool = create_test_database_pool().await;
        let user_repo = UserRepository::new(pool.clone());
        let cred_repo = CredentialRepository::new(pool.clone());
        
        let user = create_test_user();
        user_repo.create(&user).await.unwrap();
        
        let credential = create_test_credential_with_user_id(user.id);
        cred_repo.create(&credential).await.unwrap();
        
        // Verify credential exists
        let creds_before = cred_repo.get_by_user_id(&user.id).await.unwrap();
        assert_eq!(creds_before.len(), 1);
        
        // When - Delete user (should cascade delete credentials)
        user_repo.delete(&user.id).await.unwrap();
        
        // Then - Verify credentials are also deleted
        let creds_after = cred_repo.get_by_user_id(&user.id).await.unwrap();
        assert_eq!(creds_after.len(), 0);
    }
}
```

## 4. End-to-End Test Specifications

### 4.1 Complete User Flow Tests

```rust
#[cfg(test)]
mod e2e_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_complete_registration_and_authentication_flow() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let username = "e2e_test@example.com";
        let display_name = "E2E Test User";
        
        // Step 1: Begin Registration
        let reg_begin_req = RegistrationBeginRequest {
            username: username.to_string(),
            display_name: display_name.to_string(),
            user_verification: "required".to_string(),
            attestation: "direct".to_string(),
        };
        
        let reg_begin_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/register/begin")
                .set_json(&reg_begin_req)
                .to_request()
        ).await;
        
        assert_eq!(reg_begin_resp.status(), 200);
        let reg_begin_response: RegistrationBeginResponse = test::read_body_json(reg_begin_resp).await;
        
        // Step 2: Complete Registration
        let attestation = create_test_attestation_response(&reg_begin_response.challenge);
        let reg_finish_req = RegistrationFinishRequest {
            credential: attestation,
            user: User {
                id: reg_begin_response.user.id,
                name: reg_begin_response.user.name,
            },
        };
        
        let reg_finish_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/register/finish")
                .set_json(&reg_finish_req)
                .to_request()
        ).await;
        
        assert_eq!(reg_finish_resp.status(), 200);
        
        // Step 3: Begin Authentication
        let auth_begin_req = AuthenticationBeginRequest {
            username: username.to_string(),
            user_verification: "required".to_string(),
        };
        
        let auth_begin_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/begin")
                .set_json(&auth_begin_req)
                .to_request()
        ).await;
        
        assert_eq!(auth_begin_resp.status(), 200);
        let auth_begin_response: AuthenticationBeginResponse = test::read_body_json(auth_begin_resp).await;
        
        // Step 4: Complete Authentication
        let assertion = create_test_assertion_response(
            &auth_begin_response.challenge,
            &auth_begin_response.allow_credentials[0]
        );
        let auth_finish_req = AuthenticationFinishRequest {
            credential: assertion,
        };
        
        let auth_finish_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/finish")
                .set_json(&auth_finish_req)
                .to_request()
        ).await;
        
        // Then - Verify successful authentication
        assert_eq!(auth_finish_resp.status(), 200);
        let auth_finish_response: AuthenticationFinishResponse = test::read_body_json(auth_finish_resp).await;
        assert_eq!(auth_finish_response.status, "ok");
        assert_eq!(auth_finish_response.user.name, username);
    }
}
```

### 4.2 Security Attack Simulations

```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_replay_attack_prevention() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let (user, challenge) = setup_authentication_flow(&app).await;
        
        // Create valid assertion
        let assertion = create_test_assertion_response(&challenge, &user.credentials[0]);
        
        // First authentication should succeed
        let first_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/finish")
                .set_json(&AuthenticationFinishRequest { credential: assertion.clone() })
                .to_request()
        ).await;
        assert_eq!(first_resp.status(), 200);
        
        // When - Try to replay the same assertion
        let replay_resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/authenticate/finish")
                .set_json(&AuthenticationFinishRequest { credential: assertion })
                .to_request()
        ).await;
        
        // Then - Replay should be rejected
        assert_eq!(replay_resp.status(), 401);
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let req_body = RegistrationBeginRequest {
            username: "ratelimit_test@example.com".to_string(),
            display_name: "Rate Limit Test".to_string(),
            user_verification: "required".to_string(),
            attestation: "direct".to_string(),
        };
        
        // When - Make rapid requests
        let mut responses = Vec::new();
        for _ in 0..100 {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/webauthn/register/begin")
                    .set_json(&req_body)
                    .to_request()
            ).await;
            responses.push(resp.status());
        }
        
        // Then - Should be rate limited after threshold
        let success_count = responses.iter().filter(|&&s| s == 200).count();
        let rate_limited_count = responses.iter().filter(|&&s| s == 429).count();
        
        assert!(success_count > 0); // Some requests should succeed
        assert!(rate_limited_count > 0); // Some should be rate limited
    }
    
    #[tokio::test]
    async fn test_malformed_payload_handling() {
        // Given
        let app = test::init_service(create_test_app()).await;
        
        // Test various malformed payloads
        let test_cases = vec![
            ("{}", "Empty object"),
            ("{\"invalid\": \"field\"}", "Invalid fields"),
            ("{\"username\": null}", "Null values"),
            ("{\"username\": \"a\".repeat(300)}", "Oversized fields"),
        ];
        
        for (payload, description) in test_cases {
            // When
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/webauthn/register/begin")
                    .insert_header(("content-type", "application/json"))
                    .set_payload(payload)
                    .to_request()
            ).await;
            
            // Then
            assert_eq!(resp.status(), 400, "Failed for case: {}", description);
        }
    }
}
```

## 5. Performance Test Specifications

### 5.1 Load Testing

```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_concurrent_registrations() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let concurrent_users = 100;
        
        // When
        let handles: Vec<_> = (0..concurrent_users)
            .map(|i| {
                let app = app.clone();
                tokio::spawn(async move {
                    let username = format!("perf_test_{}@example.com", i);
                    let req_body = RegistrationBeginRequest {
                        username,
                        display_name: format!("Performance Test {}", i),
                        user_verification: "required".to_string(),
                        attestation: "direct".to_string(),
                    };
                    
                    let start = Instant::now();
                    let resp = test::call_service(
                        &app,
                        test::TestRequest::post()
                            .uri("/webauthn/register/begin")
                            .set_json(&req_body)
                            .to_request()
                    ).await;
                    let duration = start.elapsed();
                    
                    (resp.status(), duration)
                })
            })
            .collect();
        
        // Then
        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        
        let success_count = results.iter().filter(|(status, _)| *status == 200).count();
        let avg_duration = results.iter().map(|(_, d)| *d).sum::<Duration>() / results.len() as u32;
        
        assert_eq!(success_count, concurrent_users);
        assert!(avg_duration < Duration::from_millis(100)); // Average under 100ms
    }
    
    #[tokio::test]
    async fn test_memory_usage_under_load() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let initial_memory = get_memory_usage();
        
        // When - Perform many operations
        for i in 0..1000 {
            let username = format!("memory_test_{}@example.com", i);
            let req_body = RegistrationBeginRequest {
                username,
                display_name: format!("Memory Test {}", i),
                user_verification: "required".to_string(),
                attestation: "direct".to_string(),
            };
            
            let _ = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/webauthn/register/begin")
                    .set_json(&req_body)
                    .to_request()
            ).await;
        }
        
        // Then
        let final_memory = get_memory_usage();
        let memory_increase = final_memory - initial_memory;
        
        // Memory increase should be reasonable (less than 100MB)
        assert!(memory_increase < 100 * 1024 * 1024);
    }
}
```

## 6. Compliance Test Specifications

### 6.1 FIDO2 Specification Compliance

```rust
#[cfg(test)]
mod compliance_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_webauthn_response_format_compliance() {
        // Given
        let app = test::init_service(create_test_app()).await;
        let req_body = RegistrationBeginRequest {
            username: "compliance_test@example.com".to_string(),
            display_name: "Compliance Test".to_string(),
            user_verification: "required".to_string(),
            attestation: "direct".to_string(),
        };
        
        // When
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/webauthn/register/begin")
                .set_json(&req_body)
                .to_request()
        ).await;
        
        // Then - Verify response format matches FIDO2 specification
        assert_eq!(resp.status(), 200);
        
        let response: RegistrationBeginResponse = test::read_body_json(resp).await;
        
        // Required fields per FIDO2 spec
        assert!(!response.challenge.is_empty());
        assert!(response.rp.id.is_some());
        assert!(response.rp.name.is_some());
        assert!(response.user.id.is_some());
        assert!(!response.user.name.is_empty());
        assert!(!response.user.display_name.is_empty());
        assert!(!response.pub_key_cred_params.is_empty());
        assert!(response.timeout > 0);
        assert!(response.authenticator_selection.is_some());
    }
    
    #[tokio::test]
    async fn test_attestation_format_support() {
        // Test support for different attestation formats
        let attestation_formats = vec!["none", "indirect", "direct", "enterprise"];
        
        for format in attestation_formats {
            let app = test::init_service(create_test_app()).await;
            let req_body = RegistrationBeginRequest {
                username: format!("attestation_{}_test@example.com", format),
                display_name: format!("Attestation {} Test", format),
                user_verification: "required".to_string(),
                attestation: format.to_string(),
            };
            
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/webauthn/register/begin")
                    .set_json(&req_body)
                    .to_request()
            ).await;
            
            assert_eq!(resp.status(), 200, "Failed for attestation format: {}", format);
        }
    }
    
    #[tokio::test]
    async fn test_cryptographic_algorithm_support() {
        // Verify support for required algorithms
        let required_algorithms = vec![-7, -257, -8]; // ES256, RS256, EdDSA
        
        for alg in required_algorithms {
            let app = test::init_service(create_test_app()).await;
            let req_body = RegistrationBeginRequest {
                username: format!("algo_{}_test@example.com", alg),
                display_name: format!("Algorithm {} Test", alg),
                user_verification: "required".to_string(),
                attestation: "direct".to_string(),
            };
            
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/webauthn/register/begin")
                    .set_json(&req_body)
                    .to_request()
            ).await;
            
            assert_eq!(resp.status(), 200);
            
            let response: RegistrationBeginResponse = test::read_body_json(resp).await;
            let alg_supported = response.pub_key_cred_params
                .iter()
                .any(|param| param.alg == alg);
            
            assert!(alg_supported, "Algorithm {} not supported", alg);
        }
    }
}
```

## 7. Test Data Management

### 7.1 Test Factories

```rust
#[cfg(test)]
mod test_factories {
    use super::*;
    
    pub fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            is_active: true,
        }
    }
    
    pub fn create_test_credential() -> Credential {
        Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: base64url_encode(&generate_random_bytes(32)),
            credential_public_key: generate_es256_public_key(),
            attestation_type: "packed".to_string(),
            aaguid: Some(generate_random_bytes(16)),
            sign_count: 0,
            transports: Some(vec!["internal".to_string()]),
            created_at: Utc::now(),
            last_used: None,
            is_backup_eligible: false,
            is_backed_up: false,
            user_verification: true,
            is_active: true,
        }
    }
    
    pub fn create_test_challenge() -> Challenge {
        Challenge {
            id: Uuid::new_v4(),
            challenge_id: generate_random_bytes(32),
            user_id: Some(Uuid::new_v4()),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
            created_at: Utc::now(),
            is_used: false,
        }
    }
    
    pub fn create_valid_attestation_response(challenge: &str) -> AttestationResponse {
        // Create a valid attestation response for testing
        AttestationResponse {
            id: base64url_encode(&generate_random_bytes(32)),
            raw_id: base64url_encode(&generate_random_bytes(32)),
            r#type: "public-key".to_string(),
            response: AttestationResponseData {
                attestation_object: create_test_attestation_object(challenge),
                client_data_json: create_test_client_data_json(challenge, "webauthn.create"),
            },
        }
    }
    
    pub fn create_valid_assertion_response(challenge: &str, credential_id: &str) -> AssertionResponse {
        AssertionResponse {
            id: credential_id.to_string(),
            raw_id: credential_id.to_string(),
            r#type: "public-key".to_string(),
            response: AssertionResponseData {
                authenticator_data: create_test_authenticator_data(),
                client_data_json: create_test_client_data_json(challenge, "webauthn.get"),
                signature: create_test_signature(),
                user_handle: Some(base64url_encode(&generate_random_bytes(32))),
            },
        }
    }
}
```

## 8. Test Execution and Reporting

### 8.1 Test Configuration

```toml
# Cargo.toml test configuration
[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tokio-test = "0.4"
serial_test = "3.0"
proptest = "1.4"
criterion = "0.5"

[[bench]]
name = "webauthn_benchmarks"
harness = false
```

### 8.2 CI/CD Integration

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
    
    - name: Run formatting check
      run: cargo fmt --all -- --check
    
    - name: Run clippy
      run: cargo clippy --all-targets --all-features -- -D warnings
    
    - name: Run unit tests
      run: cargo test --lib --bins
    
    - name: Run integration tests
      run: cargo test --test '*'
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test
    
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out Xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./cobertura.xml
```

This comprehensive test specification provides a solid foundation for implementing a thoroughly tested FIDO2/WebAuthn Relying Party Server with high confidence in security, compliance, and reliability.