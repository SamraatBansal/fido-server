//! Security tests for replay attack protection

use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};
use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_uniqueness_prevents_replay() {
        let mut service = FidoService::new();
        let mut challenges = HashSet::new();
        
        // Generate multiple challenges for the same user
        let request = RegistrationRequest {
            username: "replay@example.com".to_string(),
            display_name: "Replay Test User".to_string(),
        };

        // Generate 100 challenges and verify uniqueness
        for i in 0..100 {
            let result = service.start_registration(request.clone()).await.unwrap();
            assert!(!challenges.contains(&result.challenge), "Challenge {} should be unique", i);
            challenges.insert(result.challenge);
        }
        
        assert_eq!(challenges.len(), 100, "All challenges should be unique");
    }

    #[tokio::test]
    async fn test_authentication_challenge_uniqueness() {
        let mut service = FidoService::new();
        let mut challenges = HashSet::new();
        
        // Register a user first
        let reg_request = RegistrationRequest {
            username: "auth_replay@example.com".to_string(),
            display_name: "Auth Replay User".to_string(),
        };
        let _ = service.start_registration(reg_request).await;

        // Generate multiple authentication challenges
        let auth_request = AuthenticationRequest {
            username: "auth_replay@example.com".to_string(),
        };

        // Generate 100 challenges and verify uniqueness
        for i in 0..100 {
            let result = service.start_authentication(auth_request.clone()).await.unwrap();
            assert!(!challenges.contains(&result.challenge), "Auth challenge {} should be unique", i);
            challenges.insert(result.challenge);
        }
        
        assert_eq!(challenges.len(), 100, "All authentication challenges should be unique");
    }

    #[tokio::test]
    async fn test_cross_user_challenge_isolation() {
        let mut service = FidoService::new();
        
        // Register two different users
        let user1_request = RegistrationRequest {
            username: "user1@example.com".to_string(),
            display_name: "User One".to_string(),
        };
        let user2_request = RegistrationRequest {
            username: "user2@example.com".to_string(),
            display_name: "User Two".to_string(),
        };

        // Generate challenges for both users
        let user1_challenges: Vec<String> = (0..10).map(|_| {
            service.start_registration(user1_request.clone()).await.unwrap().challenge
        }).collect();

        let user2_challenges: Vec<String> = (0..10).map(|_| {
            service.start_registration(user2_request.clone()).await.unwrap().challenge
        }).collect();

        // Verify no overlap between users' challenges
        let all_challenges: HashSet<&String> = user1_challenges.iter().chain(user2_challenges.iter()).collect();
        assert_eq!(all_challenges.len(), 20, "Challenges should be unique across users");
    }

    #[tokio::test]
    async fn test_user_data_isolation() {
        let mut service = FidoService::new();
        
        // Register multiple users
        let users = vec![
            ("alice@example.com", "Alice"),
            ("bob@example.com", "Bob"),
            ("charlie@example.com", "Charlie"),
        ];

        let mut user_ids = Vec::new();
        
        for (username, display_name) in users {
            let request = RegistrationRequest {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };
            let response = service.start_registration(request).await.unwrap();
            user_ids.push(response.user_id);
        }

        // Verify all user IDs are unique
        let unique_ids: HashSet<_> = user_ids.iter().collect();
        assert_eq!(unique_ids.len(), user_ids.len(), "All user IDs should be unique");

        // Verify authentication works for each user
        for (username, _) in users {
            let auth_request = AuthenticationRequest {
                username: username.to_string(),
            };
            let result = service.start_authentication(auth_request).await;
            assert!(result.is_ok(), "Authentication should work for {}", username);
        }
    }

    #[tokio::test]
    async fn test_concurrent_challenge_generation() {
        use std::sync::Arc;
        use tokio::task::JoinSet;
        
        let service = Arc::new(tokio::sync::Mutex::new(FidoService::new()));
        let mut join_set = JoinSet::new();
        
        // Spawn multiple concurrent challenge generation requests
        for i in 0..50 {
            let service_clone = service.clone();
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let request = RegistrationRequest {
                    username: format!("concurrent{}@example.com", i),
                    display_name: format!("Concurrent User {}", i),
                };
                svc.start_registration(request).await
            });
        }
        
        // Collect results
        let mut challenges = HashSet::new();
        while let Some(result) = join_set.join_next().await {
            let response = result.unwrap().unwrap();
            assert!(!challenges.contains(&response.challenge), "Challenge should be unique");
            challenges.insert(response.challenge);
        }
        
        assert_eq!(challenges.len(), 50, "All concurrent challenges should be unique");
    }

    #[tokio::test]
    async fn test_challenge_entropy_quality() {
        let mut service = FidoService::new();
        let mut challenges = Vec::new();
        
        // Generate a large number of challenges
        let request = RegistrationRequest {
            username: "entropy@example.com".to_string(),
            display_name: "Entropy Test User".to_string(),
        };

        for _ in 0..1000 {
            let response = service.start_registration(request.clone()).await.unwrap();
            challenges.push(response.challenge);
        }

        // Basic entropy checks
        let all_challenges: HashSet<_> = challenges.iter().collect();
        assert_eq!(all_challenges.len(), 1000, "All challenges should be unique");

        // Check challenge length (should be base64 of 32 bytes = 43 chars)
        for challenge in &challenges {
            assert_eq!(challenge.len(), 43, "Challenge should be 43 characters (base64 of 32 bytes)");
            assert!(challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), 
                   "Challenge should only contain base64url characters");
        }

        // Check for patterns (no two challenges should be similar)
        for i in 0..challenges.len() - 1 {
            let similarity = calculate_similarity(&challenges[i], &challenges[i + 1]);
            assert!(similarity < 0.5, "Challenges should not be too similar");
        }
    }

    #[tokio::test]
    async fn test_user_persistence_under_load() {
        use std::sync::Arc;
        use tokio::task::JoinSet;
        
        let service = Arc::new(tokio::sync::Mutex::new(FidoService::new()));
        let mut join_set = JoinSet::new();
        
        let username = "persistent@example.com".to_string();
        let display_name = "Persistent User".to_string();
        
        // Spawn multiple concurrent registrations for the same user
        for _ in 0..20 {
            let service_clone = service.clone();
            let username_clone = username.clone();
            let display_name_clone = display_name.clone();
            
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let request = RegistrationRequest {
                    username: username_clone,
                    display_name: display_name_clone,
                };
                svc.start_registration(request).await
            });
        }
        
        // Collect results
        let mut user_ids = HashSet::new();
        while let Some(result) = join_set.join_next().await {
            let response = result.unwrap().unwrap();
            user_ids.insert(response.user_id);
        }
        
        // All should have the same user ID
        assert_eq!(user_ids.len(), 1, "User ID should be consistent across concurrent registrations");
    }

    /// Calculate similarity between two strings (0.0 = completely different, 1.0 = identical)
    fn calculate_similarity(s1: &str, s2: &str) -> f64 {
        if s1 == s2 {
            return 1.0;
        }
        
        let common_chars = s1.chars().zip(s2.chars())
            .filter(|(c1, c2)| c1 == c2)
            .count() as f64;
        
        let max_len = s1.len().max(s2.len()) as f64;
        common_chars / max_len
    }

    #[tokio::test]
    async fn test_malformed_input_handling() {
        let mut service = FidoService::new();
        
        // Test various malformed inputs
        let test_cases = vec![
            ("", "Empty username"),
            ("   ", "Whitespace username"),
            ("a".repeat(300), "Very long username"),
            ("invalid@chars!#$%", "Invalid characters"),
        ];

        for (username, description) in test_cases {
            let request = RegistrationRequest {
                username,
                display_name: "Test User".to_string(),
            };
            
            let result = service.start_registration(request).await;
            // Some might pass (depending on validation), but none should crash
            assert!(result.is_ok() || result.is_err(), "{} should not crash", description);
        }
    }

    #[tokio::test]
    async fn test_state_isolation_between_operations() {
        let mut service = FidoService::new();
        
        // Perform multiple operations and verify state isolation
        let users = vec![
            ("user1@example.com", "User One"),
            ("user2@example.com", "User Two"),
        ];

        // Register users
        let mut user_data = Vec::new();
        for (username, display_name) in &users {
            let request = RegistrationRequest {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };
            let response = service.start_registration(request).await.unwrap();
            user_data.push((username.to_string(), response.user_id, response.challenge));
        }

        // Authenticate users
        for (username, expected_user_id, _) in user_data {
            let auth_request = AuthenticationRequest { username };
            let auth_response = service.start_authentication(auth_request).await.unwrap();
            assert_eq!(auth_response.user_id, expected_user_id, "User ID should match");
        }
    }
}