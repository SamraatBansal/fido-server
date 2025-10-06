//! Test helper functions

use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};
use std::collections::HashSet;

/// Helper to create a user and return their ID
pub async fn create_user(service: &mut FidoService, username: &str, display_name: &str) -> uuid::Uuid {
    let request = RegistrationRequest {
        username: username.to_string(),
        display_name: display_name.to_string(),
    };
    
    let response = service.start_registration(request).await.unwrap();
    response.user_id
}

/// Helper to create multiple users
pub async fn create_multiple_users(
    service: &mut FidoService, 
    count: usize
) -> Vec<(String, uuid::Uuid)> {
    let mut users = Vec::new();
    
    for i in 0..count {
        let username = format!("user{}@example.com", i);
        let display_name = format!("User {}", i);
        let user_id = create_user(service, &username, &display_name).await;
        users.push((username, user_id));
    }
    
    users
}

/// Helper to generate multiple challenges and verify uniqueness
pub async fn generate_unique_challenges(
    service: &mut FidoService,
    count: usize,
    username: &str,
    display_name: &str,
) -> HashSet<String> {
    let mut challenges = HashSet::new();
    let request = RegistrationRequest {
        username: username.to_string(),
        display_name: display_name.to_string(),
    };
    
    for _ in 0..count {
        let response = service.start_registration(request.clone()).await.unwrap();
        assert!(!challenges.contains(&response.challenge), "Challenge should be unique");
        challenges.insert(response.challenge);
    }
    
    challenges
}

/// Helper to generate multiple authentication challenges
pub async fn generate_unique_auth_challenges(
    service: &mut FidoService,
    count: usize,
    username: &str,
) -> HashSet<String> {
    let mut challenges = HashSet::new();
    let request = AuthenticationRequest {
        username: username.to_string(),
    };
    
    for _ in 0..count {
        let response = service.start_authentication(request.clone()).await.unwrap();
        assert!(!challenges.contains(&response.challenge), "Auth challenge should be unique");
        challenges.insert(response.challenge);
    }
    
    challenges
}

/// Helper to verify challenge format
pub fn verify_challenge_format(challenge: &str) -> bool {
    // Should be 43 characters (base64 of 32 bytes)
    if challenge.len() != 43 {
        return false;
    }
    
    // Should only contain base64url characters
    challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Helper to calculate string similarity (for entropy testing)
pub fn calculate_similarity(s1: &str, s2: &str) -> f64 {
    if s1 == s2 {
        return 1.0;
    }
    
    let common_chars = s1.chars().zip(s2.chars())
        .filter(|(c1, c2)| c1 == c2)
        .count() as f64;
    
    let max_len = s1.len().max(s2.len()) as f64;
    common_chars / max_len
}

/// Helper to test error messages
pub fn assert_error_message_contains(result: Result<fido_server::RegistrationResponse, fido_server::AppError>, expected: &str) {
    match result {
        Err(fido_server::AppError::InvalidRequest(msg)) => {
            assert!(msg.contains(expected), "Error message should contain '{}', got: {}", expected, msg);
        }
        _ => panic!("Expected InvalidRequest error containing '{}'", expected),
    }
}

/// Helper to test authentication error messages
pub fn assert_auth_error_message_contains(result: Result<fido_server::AuthenticationResponse, fido_server::AppError>, expected: &str) {
    match result {
        Err(fido_server::AppError::AuthenticationFailed(msg)) => {
            assert!(msg.contains(expected), "Error message should contain '{}', got: {}", expected, msg);
        }
        _ => panic!("Expected AuthenticationFailed error containing '{}'", expected),
    }
}

/// Helper to run a test with timeout
pub async fn with_timeout<F, T>(duration: std::time::Duration, future: F) -> Result<T, &'static str>
where
    F: std::future::Future<Output = T>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err("Test timed out"),
    }
}

/// Helper to create a test service with pre-populated data
pub async fn create_test_service_with_user() -> (FidoService, String, uuid::Uuid) {
    let mut service = FidoService::new();
    let username = "test@example.com".to_string();
    let display_name = "Test User".to_string();
    
    let user_id = create_user(&mut service, &username, &display_name).await;
    
    (service, username, user_id)
}

/// Helper to verify user persistence
pub async fn verify_user_persistence(service: &mut FidoService, username: &str) -> bool {
    let request = RegistrationRequest {
        username: username.to_string(),
        display_name: "Test User".to_string(),
    };
    
    let response1 = service.start_registration(request.clone()).await.unwrap();
    let response2 = service.start_registration(request).await.unwrap();
    
    response1.user_id == response2.user_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_helper_functions() {
        let mut service = FidoService::new();
        
        // Test user creation
        let user_id = create_user(&mut service, "helper@example.com", "Helper User").await;
        assert_ne!(user_id, uuid::Uuid::nil());
        
        // Test multiple user creation
        let users = create_multiple_users(&mut service, 5).await;
        assert_eq!(users.len(), 5);
        
        // Verify all user IDs are unique
        let user_ids: HashSet<_> = users.iter().map(|(_, id)| id).collect();
        assert_eq!(user_ids.len(), 5);
    }

    #[test]
    fn test_challenge_format_verification() {
        assert!(verify_challenge_format("YWJjZGVmZ2hpams=")); // 16 bytes = 24 chars
        assert!(!verify_challenge_format("")); // Empty
        assert!(!verify_challenge_format("invalid@challenge")); // Invalid chars
        assert!(!verify_challenge_format("short")); // Too short
    }

    #[test]
    fn test_similarity_calculation() {
        assert_eq!(calculate_similarity("hello", "hello"), 1.0);
        assert_eq!(calculate_similarity("hello", "world"), 0.0);
        assert!(calculate_similarity("hello", "hallo") > 0.5);
        assert!(calculate_similarity("abc", "xyz") < 0.5);
    }

    #[tokio::test]
    async fn test_timeout_helper() {
        let quick_future = async { 42 };
        let result = with_timeout(std::time::Duration::from_millis(100), quick_future).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        let slow_future = async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            42
        };
        let result = with_timeout(std::time::Duration::from_millis(50), slow_future).await;
        assert!(result.is_err());
    }
}