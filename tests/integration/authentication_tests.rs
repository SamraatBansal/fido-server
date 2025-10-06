//! Authentication integration tests

use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_successful_authentication() {
        let mut service = FidoService::new();
        
        // First register a user
        let reg_request = RegistrationRequest {
            username: "auth@example.com".to_string(),
            display_name: "Auth User".to_string(),
        };
        let _ = service.start_registration(reg_request).await;

        // Then authenticate
        let auth_request = AuthenticationRequest {
            username: "auth@example.com".to_string(),
        };

        let result = service.start_authentication(auth_request).await;
        assert!(result.is_ok(), "Authentication should succeed");
        
        let response = result.unwrap();
        assert!(!response.challenge.is_empty(), "Challenge should not be empty");
        assert_ne!(response.user_id, uuid::Uuid::nil(), "User ID should be valid");
    }

    #[tokio::test]
    async fn test_authentication_nonexistent_user() {
        let mut service = FidoService::new();
        let request = AuthenticationRequest {
            username: "nonexistent@example.com".to_string(),
        };

        let result = service.start_authentication(request).await;
        assert!(result.is_err(), "Authentication with non-existent user should fail");
    }

    #[tokio::test]
    async fn test_authentication_empty_username() {
        let mut service = FidoService::new();
        let request = AuthenticationRequest {
            username: "".to_string(),
        };

        let result = service.start_authentication(request).await;
        assert!(result.is_err(), "Authentication with empty username should fail");
    }

    #[tokio::test]
    async fn test_multiple_authentications() {
        let mut service = FidoService::new();
        
        // Register a user
        let reg_request = RegistrationRequest {
            username: "multi@example.com".to_string(),
            display_name: "Multi Auth User".to_string(),
        };
        let _ = service.start_registration(reg_request).await;

        // Authenticate multiple times
        let auth_request = AuthenticationRequest {
            username: "multi@example.com".to_string(),
        };

        for i in 0..5 {
            let result = service.start_authentication(auth_request.clone()).await;
            assert!(result.is_ok(), "Authentication {} should succeed", i + 1);
            
            let response = result.unwrap();
            assert!(!response.challenge.is_empty(), "Challenge {} should not be empty", i + 1);
        }
    }

    #[tokio::test]
    async fn test_authentication_challenge_uniqueness() {
        let mut service = FidoService::new();
        
        // Register a user
        let reg_request = RegistrationRequest {
            username: "unique@example.com".to_string(),
            display_name: "Unique Auth User".to_string(),
        };
        let _ = service.start_registration(reg_request).await;

        // Get multiple authentication challenges
        let auth_request = AuthenticationRequest {
            username: "unique@example.com".to_string(),
        };

        let result1 = service.start_authentication(auth_request.clone()).await.unwrap();
        let result2 = service.start_authentication(auth_request).await.unwrap();
        
        assert_ne!(result1.challenge, result2.challenge, "Authentication challenges should be unique");
        assert_eq!(result1.user_id, result2.user_id, "User ID should be the same");
    }

    #[tokio::test]
    async fn test_user_registration_then_authentication_flow() {
        let mut service = FidoService::new();
        
        // Complete registration flow
        let reg_request = RegistrationRequest {
            username: "flow@example.com".to_string(),
            display_name: "Flow User".to_string(),
        };
        let reg_response = service.start_registration(reg_request).await.unwrap();
        
        // Complete authentication flow
        let auth_request = AuthenticationRequest {
            username: "flow@example.com".to_string(),
        };
        let auth_response = service.start_authentication(auth_request).await.unwrap();
        
        // Verify user ID consistency
        assert_eq!(reg_response.user_id, auth_response.user_id, "User ID should be consistent across flows");
        
        // Verify both challenges are unique
        assert_ne!(reg_response.challenge, auth_response.challenge, "Registration and authentication challenges should be different");
    }

    #[tokio::test]
    async fn test_concurrent_authentications() {
        use std::sync::Arc;
        use tokio::task::JoinSet;
        
        let mut service = FidoService::new();
        
        // Register a user first
        let reg_request = RegistrationRequest {
            username: "concurrent@example.com".to_string(),
            display_name: "Concurrent User".to_string(),
        };
        let _ = service.start_registration(reg_request).await;
        
        let service = Arc::new(tokio::sync::Mutex::new(service));
        let mut join_set = JoinSet::new();
        
        // Spawn multiple concurrent authentication requests
        for i in 0..10 {
            let service_clone = service.clone();
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let request = AuthenticationRequest {
                    username: "concurrent@example.com".to_string(),
                };
                svc.start_authentication(request).await
            });
        }
        
        // Collect results
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }
        
        // All should succeed
        assert_eq!(results.len(), 10, "All authentications should complete");
        for result in results {
            assert!(result.is_ok(), "Each authentication should succeed");
        }
    }

    #[tokio::test]
    async fn test_authentication_after_multiple_registrations() {
        let mut service = FidoService::new();
        
        // Register the same user multiple times
        let reg_request = RegistrationRequest {
            username: "multi_reg@example.com".to_string(),
            display_name: "Multi Registration User".to_string(),
        };
        
        let reg_response1 = service.start_registration(reg_request.clone()).await.unwrap();
        let reg_response2 = service.start_registration(reg_request).await.unwrap();
        
        // Verify user ID consistency across registrations
        assert_eq!(reg_response1.user_id, reg_response2.user_id, "User ID should be consistent across multiple registrations");
        
        // Authentication should still work
        let auth_request = AuthenticationRequest {
            username: "multi_reg@example.com".to_string(),
        };
        let auth_response = service.start_authentication(auth_request).await.unwrap();
        
        assert_eq!(reg_response1.user_id, auth_response.user_id, "Authentication should use the same user ID");
    }
}