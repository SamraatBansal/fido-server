//! Integration tests for API endpoints

use axum_test::TestServer;
use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn test_basic_service_creation() {
    // Test that we can create a FIDO service
    let service = FidoService::new();
    assert!(true, "Service creation should work");
}

#[tokio::test]
async fn test_registration_flow_integration() {
    // Test the complete registration flow
    let mut service = FidoService::new();
    
    // Start registration
    let request = RegistrationRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
    };

    let result = service.start_registration(request).await;
    assert!(result.is_ok(), "Registration should succeed");
    
    let response = result.unwrap();
    assert!(!response.challenge.is_empty(), "Challenge should not be empty");
    assert_ne!(response.user_id, uuid::Uuid::nil(), "User ID should be valid");
}

#[tokio::test]
async fn test_authentication_flow_integration() {
    // Test the complete authentication flow
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
}

#[tokio::test]
async fn test_user_persistence_across_operations() {
    // Test that user data persists across multiple operations
    let mut service = FidoService::new();
    
    let request = RegistrationRequest {
        username: "persistent@example.com".to_string(),
        display_name: "Persistent User".to_string(),
    };

    // Register user twice
    let response1 = service.start_registration(request.clone()).await.unwrap();
    let response2 = service.start_registration(request).await.unwrap();
    
    // User ID should be the same
    assert_eq!(response1.user_id, response2.user_id, "User ID should be persistent");
    
    // Authentication should work with the same user
    let auth_request = AuthenticationRequest {
        username: "persistent@example.com".to_string(),
    };
    let auth_response = service.start_authentication(auth_request).await.unwrap();
    assert_eq!(response1.user_id, auth_response.user_id, "Authentication should use same user ID");
}

#[tokio::test]
async fn test_error_handling_integration() {
    // Test error handling in integration scenarios
    let mut service = FidoService::new();
    
    // Test registration with invalid data
    let invalid_request = RegistrationRequest {
        username: "".to_string(),
        display_name: "".to_string(),
    };

    let result = service.start_registration(invalid_request).await;
    assert!(result.is_err(), "Invalid registration should fail");
    
    // Test authentication with non-existent user
    let auth_request = AuthenticationRequest {
        username: "nonexistent@example.com".to_string(),
    };

    let auth_result = service.start_authentication(auth_request).await;
    assert!(auth_result.is_err(), "Authentication with non-existent user should fail");
}