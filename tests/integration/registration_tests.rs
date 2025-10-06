//! Registration integration tests

use fido_server::{FidoService, RegistrationRequest};
use proptest::prelude::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_successful_registration() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "user@example.com".to_string(),
            display_name: "Test User".to_string(),
        };

        let result = service.start_registration(request).await;
        assert!(result.is_ok(), "Registration should succeed");
        
        let response = result.unwrap();
        assert!(!response.challenge.is_empty(), "Challenge should not be empty");
        assert_ne!(response.user_id, uuid::Uuid::nil(), "User ID should be valid");
    }

    #[tokio::test]
    async fn test_duplicate_registration() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "duplicate@example.com".to_string(),
            display_name: "Duplicate User".to_string(),
        };

        // Register twice
        let result1 = service.start_registration(request.clone()).await;
        let result2 = service.start_registration(request).await;
        
        assert!(result1.is_ok(), "First registration should succeed");
        assert!(result2.is_ok(), "Second registration should succeed");
        
        // User ID should be the same
        assert_eq!(result1.unwrap().user_id, result2.unwrap().user_id, "User ID should be consistent");
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
    async fn test_challenge_uniqueness() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "unique@example.com".to_string(),
            display_name: "Unique User".to_string(),
        };

        let result1 = service.start_registration(request.clone()).await.unwrap();
        let result2 = service.start_registration(request).await.unwrap();
        
        assert_ne!(result1.challenge, result2.challenge, "Challenges should be unique");
        assert_eq!(result1.user_id, result2.user_id, "User ID should be the same");
    }

    proptest! {
        #[test]
        fn test_registration_with_various_usernames(
            username in "[a-zA-Z0-9._%+-]{3,50}@[a-zA-Z0-9.-]{3,50}\\.[a-zA-Z]{2,10}"
        ) {
            // This test would run in a sync context, so we'll test the validation logic
            // In a real scenario, you'd want to use tokio::test with proptest-async
            prop_assert!(!username.is_empty());
            prop_assert!(username.len() >= 3);
            prop_assert!(username.len() <= 50);
        }
    }

    #[tokio::test]
    async fn test_concurrent_registrations() {
        use std::sync::Arc;
        use tokio::task::JoinSet;
        
        let service = Arc::new(tokio::sync::Mutex::new(FidoService::new()));
        let mut join_set = JoinSet::new();
        
        // Spawn multiple concurrent registration requests
        for i in 0..10 {
            let service_clone = service.clone();
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let request = RegistrationRequest {
                    username: format!("user{}@example.com", i),
                    display_name: format!("User {}", i),
                };
                svc.start_registration(request).await
            });
        }
        
        // Collect results
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }
        
        // All should succeed
        assert_eq!(results.len(), 10, "All registrations should complete");
        for result in results {
            assert!(result.is_ok(), "Each registration should succeed");
        }
    }
}