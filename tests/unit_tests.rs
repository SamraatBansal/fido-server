//! Unit tests for WebAuthn service functionality
//! 
//! These tests validate the core business logic without HTTP layer

use fido_server::webauthn::*;
use fido_server::webauthn::service::{WebAuthnService, WebAuthnServiceImpl};
use std::collections::HashMap;

fn create_test_service() -> WebAuthnServiceImpl {
    let config = WebAuthnConfig {
        rp_name: "Test Corporation".to_string(),
        rp_id: "localhost".to_string(),
        rp_origin: "http://localhost:8080".to_string(),
        timeout: 60000,
    };
    WebAuthnServiceImpl::new(config)
}

#[tokio::test]
async fn test_challenge_generation() {
    let service = create_test_service();
    
    let challenge1 = service.generate_challenge();
    let challenge2 = service.generate_challenge();
    
    // Challenges should be different
    assert_ne!(challenge1, challenge2);
    
    // Challenges should be base64url encoded without padding
    assert!(!challenge1.contains('='));
    assert!(!challenge1.contains('+'));
    assert!(!challenge1.contains('/'));
    
    // Should be decodable
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&challenge1)
        .unwrap();
    assert_eq!(decoded.len(), 32); // 32 bytes = 256 bits
}

#[tokio::test]
async fn test_challenge_storage_and_validation() {
    let service = create_test_service();
    
    // Store a challenge
    let challenge = "test_challenge_123";
    service.store_challenge(
        challenge, 
        Some("testuser".to_string()), 
        ChallengeType::Registration
    ).await;
    
    // Validate the challenge
    let username = service.validate_challenge(challenge, ChallengeType::Registration).await.unwrap();
    assert_eq!(username, Some("testuser".to_string()));
    
    // Challenge should be consumed (not found on second validation)
    let result = service.validate_challenge(challenge, ChallengeType::Registration).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_challenge_type_mismatch() {
    let service = create_test_service();
    
    // Store a registration challenge
    let challenge = "test_challenge_456";
    service.store_challenge(
        challenge, 
        Some("testuser".to_string()), 
        ChallengeType::Registration
    ).await;
    
    // Try to validate as authentication challenge (should fail)
    let result = service.validate_challenge(challenge, ChallengeType::Authentication).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_user_creation_and_retrieval() {
    let service = create_test_service();
    
    // Create a user
    let user = service.get_or_create_user("newuser@example.com", "New User").await.unwrap();
    
    assert_eq!(user.username, "newuser@example.com");
    assert_eq!(user.display_name, "New User");
    assert!(!user.id.is_empty());
    
    // Retrieve the same user (should return existing)
    let user2 = service.get_or_create_user("newuser@example.com", "Different Name").await.unwrap();
    assert_eq!(user.id, user2.id); // Same user ID
    assert_eq!(user2.display_name, "New User"); // Original display name preserved
}

#[tokio::test]
async fn test_begin_registration_success() {
    let service = create_test_service();
    
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
        }),
        attestation: "direct".to_string(),
    };
    
    let response = service.begin_registration(request).await.unwrap();
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
    assert_eq!(response.rp.name, "Test Corporation");
    assert_eq!(response.user.name, "test@example.com");
    assert_eq!(response.user.display_name, "Test User");
    assert!(!response.challenge.is_empty());
    assert_eq!(response.pub_key_cred_params.len(), 3);
    assert_eq!(response.attestation, Some("direct".to_string()));
}

#[tokio::test]
async fn test_begin_registration_validation_errors() {
    let service = create_test_service();
    
    // Empty username
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };
    
    let result = service.begin_registration(request).await;
    assert!(result.is_err());
    
    // Empty display name
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };
    
    let result = service.begin_registration(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_begin_authentication_success() {
    let service = create_test_service();
    
    // First create a user
    service.get_or_create_user("test@example.com", "Test User").await.unwrap();
    
    let request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "test@example.com".to_string(),
        user_verification: Some("required".to_string()),
    };
    
    let response = service.begin_authentication(request).await.unwrap();
    
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
    assert!(!response.challenge.is_empty());
    assert_eq!(response.rp_id, "localhost");
    assert_eq!(response.user_verification, Some("required".to_string()));
}

#[tokio::test]
async fn test_begin_authentication_user_not_found() {
    let service = create_test_service();
    
    let request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "nonexistent@example.com".to_string(),
        user_verification: None,
    };
    
    let result = service.begin_authentication(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_credential_storage_and_retrieval() {
    let service = create_test_service();
    
    let credential = Credential {
        id: "test_credential".to_string(),
        user_id: "test_user".to_string(),
        public_key: vec![1, 2, 3, 4],
        sign_count: 0,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    };
    
    // Store credential
    service.store_credential(credential.clone()).await.unwrap();
    
    // Retrieve credential
    let retrieved = service.get_credential("test_credential").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, "test_credential");
    
    // Get user credentials
    let user_creds = service.get_user_credentials("test_user").await.unwrap();
    assert_eq!(user_creds.len(), 1);
    assert_eq!(user_creds[0].id, "test_credential");
}

#[tokio::test]
async fn test_sign_count_update() {
    let service = create_test_service();
    
    let credential = Credential {
        id: "test_credential".to_string(),
        user_id: "test_user".to_string(),
        public_key: vec![1, 2, 3, 4],
        sign_count: 5,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    };
    
    service.store_credential(credential).await.unwrap();
    
    // Update sign count
    service.update_sign_count("test_credential", 10).await.unwrap();
    
    // Verify update
    let updated = service.get_credential("test_credential").await.unwrap().unwrap();
    assert_eq!(updated.sign_count, 10);
    assert!(updated.last_used_at.is_some());
}

#[tokio::test]
async fn test_client_data_json_verification() {
    let service = create_test_service();
    
    // Valid client data
    let client_data = serde_json::json!({
        "challenge": "test_challenge",
        "type": "webauthn.create",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });
    
    let client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&client_data).unwrap());
    
    let challenge = service.verify_client_data_json(
        &client_data_json,
        "webauthn.create",
        "http://localhost:8080"
    ).unwrap();
    
    assert_eq!(challenge, "test_challenge");
    
    // Invalid type
    let invalid_client_data = serde_json::json!({
        "challenge": "test_challenge",
        "type": "webauthn.get", // Wrong type
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });
    
    let invalid_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&invalid_client_data).unwrap());
    
    let result = service.verify_client_data_json(
        &invalid_json,
        "webauthn.create",
        "http://localhost:8080"
    );
    assert!(result.is_err());
    
    // Invalid origin
    let invalid_origin_data = serde_json::json!({
        "challenge": "test_challenge",
        "type": "webauthn.create",
        "origin": "http://evil.com", // Wrong origin
        "clientExtensions": {}
    });
    
    let invalid_origin_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&invalid_origin_data).unwrap());
    
    let result = service.verify_client_data_json(
        &invalid_origin_json,
        "webauthn.create",
        "http://localhost:8080"
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_complete_registration_flow_unit() {
    let service = create_test_service();
    
    // Begin registration
    let begin_request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "flowtest@example.com".to_string(),
        display_name: "Flow Test User".to_string(),
        authenticator_selection: None,
        attestation: "none".to_string(),
    };
    
    let begin_response = service.begin_registration(begin_request).await.unwrap();
    let challenge = begin_response.challenge.clone();
    
    // Create mock credential
    let client_data = serde_json::json!({
        "challenge": challenge,
        "type": "webauthn.create",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });
    
    let client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&client_data).unwrap());
    
    let credential = ServerPublicKeyCredential {
        id: "flow_test_credential".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAttestationResponse {
            client_data_json,
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQAAAAAAAAAAAAAAAAAAAAAAJGNivmk3aQAAAAAjalZ3iQj8AYKvB1AYW1vYm9hdAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wAB".to_string(),
        },
        get_client_extension_results: HashMap::new(),
    };
    
    // Complete registration
    let result = service.finish_registration(credential, "").await.unwrap();
    assert_eq!(result.status, "ok");
    
    // Verify credential was stored
    let stored = service.get_credential("flow_test_credential").await.unwrap();
    assert!(stored.is_some());
}

#[tokio::test]
async fn test_complete_authentication_flow_unit() {
    let service = create_test_service();
    
    // First register a user and credential
    service.get_or_create_user("authtest@example.com", "Auth Test User").await.unwrap();
    
    let credential = Credential {
        id: "auth_test_credential".to_string(),
        user_id: "authtest@example.com".to_string(), // This should be the user ID, but we'll use username for simplicity in test
        public_key: vec![1, 2, 3, 4],
        sign_count: 0,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    };
    
    service.store_credential(credential).await.unwrap();
    
    // Begin authentication
    let auth_begin_request = ServerPublicKeyCredentialGetOptionsRequest {
        username: "authtest@example.com".to_string(),
        user_verification: None,
    };
    
    let auth_begin_response = service.begin_authentication(auth_begin_request).await.unwrap();
    let auth_challenge = auth_begin_response.challenge.clone();
    
    // Create mock assertion
    let auth_client_data = serde_json::json!({
        "challenge": auth_challenge,
        "type": "webauthn.get",
        "origin": "http://localhost:8080",
        "clientExtensions": {}
    });
    
    let auth_client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&auth_client_data).unwrap());
    
    let assertion = ServerAssertionPublicKeyCredential {
        id: "auth_test_credential".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEUCIQCdBCNL4soW_2y2n1x8rXx9n8Q9o7t3z3x3x3x3x3x3x3x3x3x3x3x3x3x3x".to_string(),
            user_handle: "".to_string(),
            client_data_json: auth_client_data_json,
        },
        get_client_extension_results: HashMap::new(),
    };
    
    // Complete authentication
    let result = service.finish_authentication(assertion).await.unwrap();
    assert_eq!(result.status, "ok");
    
    // Verify sign count was updated
    let updated = service.get_credential("auth_test_credential").await.unwrap().unwrap();
    assert_eq!(updated.sign_count, 1);
    assert!(updated.last_used_at.is_some());
}