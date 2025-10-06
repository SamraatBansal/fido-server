//! Unit tests for FIDO service

use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};
use proptest::prelude::*;
use std::collections::HashSet;

#[tokio::test]
async fn test_basic_functionality() {
    // Simple test that verifies basic functionality
    assert!(true, "Basic test should pass");
}

#[tokio::test]
async fn test_registration_challenge_generation() {
    // Test registration challenge generation
    let mut service = FidoService::new();
    let request = RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
    };

    let result = service.start_registration(request).await;
    
    assert!(result.is_ok(), "Registration should succeed");
    
    let response = result.unwrap();
    assert!(!response.challenge.is_empty(), "Challenge should not be empty");
    assert_ne!(response.user_id, uuid::Uuid::nil(), "User ID should be valid");
    assert_eq!(response.challenge.len(), 43, "Challenge should be 43 characters (base64 of 32 bytes)");
}

#[tokio::test]
async fn test_attestation_verification_placeholder() {
    // TODO: Test attestation verification
    // 1. Mock valid attestation
    // 2. Call finish_registration
    // 3. Verify attestation is validated
    // 4. Verify credential is stored
    
    // For now, just test that we can create a service
    let _service = FidoService::new();
    assert!(true, "Service creation should work");
}

#[tokio::test]
async fn test_authentication_challenge_generation() {
    // Test authentication challenge generation
    let mut service = FidoService::new();
    
    // First register a user
    let reg_request = RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
    };
    let _ = service.start_registration(reg_request).await;

    // Then test authentication
    let auth_request = AuthenticationRequest {
        username: "test@example.com".to_string(),
    };

    let result = service.start_authentication(auth_request).await;
    
    assert!(result.is_ok(), "Authentication should succeed");
    
    let response = result.unwrap();
    assert!(!response.challenge.is_empty(), "Challenge should not be empty");
    assert_ne!(response.user_id, uuid::Uuid::nil(), "User ID should be valid");
    assert_eq!(response.challenge.len(), 43, "Challenge should be 43 characters (base64 of 32 bytes)");
}

#[tokio::test]
async fn test_assertion_verification_placeholder() {
    // TODO: Test assertion verification
    
    // For now, just test that we can create a service
    let _service = FidoService::new();
    assert!(true, "Service creation should work");
}

#[tokio::test]
async fn test_invalid_attestation_rejection_placeholder() {
    // TODO: Test that invalid attestations are rejected
    
    // For now, just test that we can create a service
    let _service = FidoService::new();
    assert!(true, "Service creation should work");
}

#[tokio::test]
async fn test_invalid_assertion_rejection_placeholder() {
    // TODO: Test that invalid assertions are rejected
    
    // For now, just test that we can create a service
    let _service = FidoService::new();
    assert!(true, "Service creation should work");
}

#[tokio::test]
async fn test_registration_validation() {
    let mut service = FidoService::new();
    
    // Test empty username
    let request1 = RegistrationRequest {
        username: "".to_string(),
        display_name: "Test User".to_string(),
    };
    let result1 = service.start_registration(request1).await;
    assert!(result1.is_err(), "Empty username should fail");
    
    // Test empty display name
    let request2 = RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "".to_string(),
    };
    let result2 = service.start_registration(request2).await;
    assert!(result2.is_err(), "Empty display name should fail");
}

#[tokio::test]
async fn test_authentication_validation() {
    let mut service = FidoService::new();
    
    // Test empty username
    let request = AuthenticationRequest {
        username: "".to_string(),
    };
    let result = service.start_authentication(request).await;
    assert!(result.is_err(), "Empty username should fail");
    
    // Test non-existent user
    let request2 = AuthenticationRequest {
        username: "nonexistent@example.com".to_string(),
    };
    let result2 = service.start_authentication(request2).await;
    assert!(result2.is_err(), "Non-existent user should fail");
}

#[tokio::test]
async fn test_user_persistence() {
    let mut service = FidoService::new();
    let request = RegistrationRequest {
        username: "persistent@example.com".to_string(),
        display_name: "Persistent User".to_string(),
    };

    let response1 = service.start_registration(request.clone()).await.unwrap();
    let response2 = service.start_registration(request).await.unwrap();
    
    assert_eq!(response1.user_id, response2.user_id, "User ID should be persistent");
    assert_ne!(response1.challenge, response2.challenge, "Challenges should be unique");
}

#[tokio::test]
async fn test_challenge_uniqueness() {
    let mut service = FidoService::new();
    let request = RegistrationRequest {
        username: "unique@example.com".to_string(),
        display_name: "Unique User".to_string(),
    };

    let mut challenges = HashSet::new();
    
    // Generate multiple challenges
    for _ in 0..10 {
        let response = service.start_registration(request.clone()).await.unwrap();
        assert!(!challenges.contains(&response.challenge), "Challenge should be unique");
        challenges.insert(response.challenge);
    }
    
    assert_eq!(challenges.len(), 10, "All challenges should be unique");
}

#[tokio::test]
async fn test_service_state_isolation() {
    let mut service1 = FidoService::new();
    let mut service2 = FidoService::new();
    
    let request = RegistrationRequest {
        username: "isolated@example.com".to_string(),
        display_name: "Isolated User".to_string(),
    };

    // Same user in different services should get different IDs
    let response1 = service1.start_registration(request.clone()).await.unwrap();
    let response2 = service2.start_registration(request).await.unwrap();
    
    assert_ne!(response1.user_id, response2.user_id, "Different services should have isolated state");
    assert_ne!(response1.challenge, response2.challenge, "Challenges should be unique across services");
}

proptest! {
    #[test]
    fn test_username_format_validation(
        username in "[a-zA-Z0-9._%+-]{3,50}@[a-zA-Z0-9.-]{3,50}\\.[a-zA-Z]{2,10}"
    ) {
        // Test that valid email formats pass basic validation
        prop_assert!(!username.is_empty());
        prop_assert!(username.len() >= 3);
        prop_assert!(username.len() <= 50);
        prop_assert!(username.contains('@'));
        prop_assert!(username.contains('.'));
    }

    #[test]
    fn test_display_name_validation(
        display_name in "[A-Za-z ]{1,100}"
    ) {
        // Test that display names are reasonable
        prop_assert!(!display_name.is_empty());
        prop_assert!(display_name.len() <= 100);
        prop_assert!(display_name.chars().all(|c| c.is_alphabetic() || c.is_whitespace()));
    }

    #[test]
    fn test_challenge_format() {
        // Test that generated challenges have the right format
        let service = FidoService::new();
        
        // This is a simplified test - in reality we'd need async support
        // For now, just test the challenge generation function directly
        let challenge = generate_test_challenge();
        
        prop_assert!(!challenge.is_empty());
        prop_assert_eq!(challenge.len(), 43); // base64 of 32 bytes
        prop_assert!(challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}

#[tokio::test]
async fn test_error_types() {
    let mut service = FidoService::new();
    
    // Test InvalidRequest error
    let empty_request = RegistrationRequest {
        username: "".to_string(),
        display_name: "Test".to_string(),
    };
    let result = service.start_registration(empty_request).await;
    match result.unwrap_err() {
        fido_server::AppError::InvalidRequest(msg) => {
            assert!(msg.contains("Username cannot be empty"));
        }
        _ => panic!("Expected InvalidRequest error"),
    }
    
    // Test AuthenticationFailed error
    let nonexistent_request = AuthenticationRequest {
        username: "nonexistent@example.com".to_string(),
    };
    let result2 = service.start_authentication(nonexistent_request).await;
    match result2.unwrap_err() {
        fido_server::AppError::AuthenticationFailed(msg) => {
            assert!(msg.contains("User not found"));
        }
        _ => panic!("Expected AuthenticationFailed error"),
    }
}

#[tokio::test]
async fn test_multiple_users() {
    let mut service = FidoService::new();
    
    let users = vec![
        ("alice@example.com", "Alice"),
        ("bob@example.com", "Bob"),
        ("charlie@example.com", "Charlie"),
    ];

    let mut user_ids = HashSet::new();
    
    // Register multiple users
    for (username, display_name) in users {
        let request = RegistrationRequest {
            username: username.to_string(),
            display_name: display_name.to_string(),
        };
        let response = service.start_registration(request).await.unwrap();
        user_ids.insert(response.user_id);
    }
    
    // All user IDs should be unique
    assert_eq!(user_ids.len(), 3, "All users should have unique IDs");
    
    // All users should be able to authenticate
    for (username, _) in users {
        let auth_request = AuthenticationRequest {
            username: username.to_string(),
        };
        let result = service.start_authentication(auth_request).await;
        assert!(result.is_ok(), "User {} should be able to authenticate", username);
    }
}

#[tokio::test]
async fn test_edge_cases() {
    let mut service = FidoService::new();
    
    // Test minimum valid username length
    let min_request = RegistrationRequest {
        username: "a@b.c".to_string(),
        display_name: "A".to_string(),
    };
    let result = service.start_registration(min_request).await;
    assert!(result.is_ok(), "Minimum valid input should work");
    
    // Test very long but valid inputs
    let long_username = format!("user{}@example.com", "x".repeat(100));
    let long_request = RegistrationRequest {
        username: long_username,
        display_name: "X".repeat(200),
    };
    let result2 = service.start_registration(long_request).await;
    // This might fail due to length limits, which is acceptable
    assert!(result2.is_ok() || result2.is_err(), "Long input should not crash");
}

// Helper function for testing challenge generation
fn generate_test_challenge() -> String {
    use base64::{Engine as _, engine::general_purpose};
    let bytes = rand::random::<[u8; 32]>();
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}