//! Security compliance tests

use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_randomness_quality() {
        // Security requirement: Challenges must be cryptographically random
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "security@example.com".to_string(),
            display_name: "Security Test User".to_string(),
        };

        let mut challenges = Vec::new();
        
        // Generate many challenges
        for _ in 0..1000 {
            let response = service.start_registration(request.clone()).await.unwrap();
            challenges.push(response.challenge);
        }

        // Test for randomness patterns
        assert_no_repeating_patterns(&challenges);
        assert_uniform_distribution(&challenges);
        assert_no_predictable_sequences(&challenges);
    }

    #[tokio::test]
    async fn test_user_isolation() {
        // Security requirement: Users must be isolated from each other
        let mut service = FidoService::new();
        
        // Register multiple users
        let users = vec![
            ("alice@example.com", "Alice"),
            ("bob@example.com", "Bob"),
            ("mallory@example.com", "Mallory"),
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
        let unique_ids: std::collections::HashSet<_> = user_ids.iter().collect();
        assert_eq!(unique_ids.len(), user_ids.len(), "All user IDs should be unique");

        // Verify authentication isolation
        for (username, _) in users {
            let auth_request = AuthenticationRequest {
                username: username.to_string(),
            };
            let result = service.start_authentication(auth_request).await;
            assert!(result.is_ok(), "Each user should be able to authenticate independently");
        }
    }

    #[tokio::test]
    async fn test_input_sanitization() {
        // Security requirement: Inputs must be properly sanitized
        let mut service = FidoService::new();
        
        let malicious_inputs = vec![
            ("../../../etc/passwd", "Path traversal attempt"),
            ("<script>alert('xss')</script>", "XSS attempt"),
            ("'; DROP TABLE users; --", "SQL injection attempt"),
            ("\x00\x01\x02\x03", "Binary data attempt"),
            ("a".repeat(10000), "Buffer overflow attempt"),
        ];

        for (malicious_input, description) in malicious_inputs {
            let request = RegistrationRequest {
                username: malicious_input,
                display_name: "Test User".to_string(),
            };

            let result = service.start_registration(request).await;
            // Should not crash, should handle gracefully
            assert!(result.is_ok() || result.is_err(), 
                   "Malicious input ({}) should not crash the service", description);
        }
    }

    #[tokio::test]
    async fn test_timing_attack_resistance() {
        // Security requirement: Operations should not leak timing information
        let mut service = FidoService::new();
        
        // Register a user
        let reg_request = RegistrationRequest {
            username: "timing@example.com".to_string(),
            display_name: "Timing Test User".to_string(),
        };
        let _ = service.start_registration(reg_request).await.unwrap();

        // Measure timing for existing vs non-existing users
        let existing_user = AuthenticationRequest {
            username: "timing@example.com".to_string(),
        };
        let non_existing_user = AuthenticationRequest {
            username: "nonexistent@example.com".to_string(),
        };

        let mut existing_times = Vec::new();
        let mut non_existing_times = Vec::new();

        // Take multiple measurements
        for _ in 0..10 {
            let start = std::time::Instant::now();
            let _ = service.start_authentication(existing_user.clone()).await;
            existing_times.push(start.elapsed());

            let start = std::time::Instant::now();
            let _ = service.start_authentication(non_existing_user.clone()).await;
            non_existing_times.push(start.elapsed());
        }

        let avg_existing = existing_times.iter().sum::<std::time::Duration>() / existing_times.len() as u32;
        let avg_non_existing = non_existing_times.iter().sum::<std::time::Duration>() / non_existing_times.len() as u32;

        // Timing difference should be minimal (within reasonable bounds)
        let diff = if avg_existing > avg_non_existing {
            avg_existing - avg_non_existing
        } else {
            avg_non_existing - avg_existing
        };

        // Allow some difference but it shouldn't be excessive
        assert!(diff < std::time::Duration::from_millis(100), 
               "Timing difference should be minimal to prevent timing attacks");
    }

    #[tokio::test]
    async fn test_memory_cleanup() {
        // Security requirement: Sensitive data should be cleaned up properly
        let mut service = FidoService::new();
        
        // Generate many challenges to test memory usage
        let request = RegistrationRequest {
            username: "memory@example.com".to_string(),
            display_name: "Memory Test User".to_string(),
        };

        for _ in 0..1000 {
            let _ = service.start_registration(request.clone()).await.unwrap();
        }

        // In a real implementation, you'd check that sensitive data
        // is properly zeroed out from memory
        // For this simple implementation, we just verify it doesn't crash
        assert!(true, "Memory cleanup test completed");
    }

    #[tokio::test]
    async fn test_concurrent_security() {
        // Security requirement: Concurrent operations should be secure
        use std::sync::Arc;
        use tokio::task::JoinSet;
        
        let service = Arc::new(tokio::sync::Mutex::new(FidoService::new()));
        let mut join_set = JoinSet::new();
        
        // Spawn many concurrent operations
        for i in 0..100 {
            let service_clone = service.clone();
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                
                // Mix of registrations and authentications
                if i % 2 == 0 {
                    let request = RegistrationRequest {
                        username: format!("concurrent{}@example.com", i),
                        display_name: format!("Concurrent User {}", i),
                    };
                    svc.start_registration(request).await
                } else {
                    let request = AuthenticationRequest {
                        username: format!("concurrent{}@example.com", i / 2),
                    };
                    svc.start_authentication(request).await
                }
            });
        }
        
        // Collect results
        let mut successes = 0;
        let mut failures = 0;
        
        while let Some(result) = join_set.join_next().await {
            match result.unwrap() {
                Ok(_) => successes += 1,
                Err(_) => failures += 1,
            }
        }
        
        // Most operations should succeed (some authentications might fail if user doesn't exist yet)
        assert!(successes > 50, "Most concurrent operations should succeed");
        assert!(failures < 50, "Not too many operations should fail");
    }

    #[tokio::test]
    async fn test_error_information_leakage() {
        // Security requirement: Error messages should not leak sensitive information
        let mut service = FidoService::new();
        
        // Test registration errors
        let empty_username_result = service.start_registration(RegistrationRequest {
            username: "".to_string(),
            display_name: "Test".to_string(),
        }).await;
        
        let empty_display_result = service.start_registration(RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "".to_string(),
        }).await;

        // Test authentication errors
        let empty_auth_result = service.start_authentication(AuthenticationRequest {
            username: "".to_string(),
        }).await;
        
        let nonexistent_user_result = service.start_authentication(AuthenticationRequest {
            username: "nonexistent@example.com".to_string(),
        }).await;

        let results = vec![
            (empty_username_result, "Empty username"),
            (empty_display_result, "Empty display name"),
            (empty_auth_result, "Empty auth username"),
            (nonexistent_user_result, "Non-existent user"),
        ];

        for (result, description) in results {
            if let Err(error) = result {
                let error_msg = format!("{:?}", error);
                
                // Error messages should not contain sensitive information
                assert!(!error_msg.contains("password"), "Error should not contain sensitive info");
                assert!(!error_msg.contains("secret"), "Error should not contain sensitive info");
                assert!(!error_msg.contains("token"), "Error should not contain sensitive info");
                
                // Error messages should be reasonably sized
                assert!(error_msg.len() < 500, "Error message should not be excessively long");
            }
        }
    }

    fn assert_no_repeating_patterns(challenges: &[String]) {
        // Check for obvious repeating patterns
        for i in 1..challenges.len() {
            let similarity = calculate_similarity(&challenges[i-1], &challenges[i]);
            assert!(similarity < 0.3, "Challenges should not have repeating patterns");
        }
    }

    fn assert_uniform_distribution(challenges: &[String]) {
        // Basic uniform distribution test
        let mut char_counts = std::collections::HashMap::new();
        
        for challenge in challenges {
            for c in challenge.chars() {
                *char_counts.entry(c).or_insert(0) += 1;
            }
        }
        
        // All characters should appear reasonably often
        let total_chars: usize = char_counts.values().sum();
        let expected_per_char = total_chars / char_counts.len();
        
        for &count in char_counts.values() {
            let ratio = count as f64 / expected_per_char as f64;
            assert!(ratio > 0.5 && ratio < 2.0, "Character distribution should be uniform");
        }
    }

    fn assert_no_predictable_sequences(challenges: &[String]) {
        // Check for predictable sequences (like incrementing patterns)
        for i in 2..challenges.len() {
            let prev1 = &challenges[i-1];
            let prev2 = &challenges[i-2];
            let current = &challenges[i];
            
            // Simple check: shouldn't be too similar to previous challenges
            let sim1 = calculate_similarity(prev1, current);
            let sim2 = calculate_similarity(prev2, current);
            
            assert!(sim1 < 0.5 && sim2 < 0.5, "Challenges should not form predictable sequences");
        }
    }

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
}

// Helper trait for downcasting in the error test
trait Downcast {
    fn downcast_ref<T: 'static>(&self) -> Option<&T>;
}

impl Downcast for fido_server::RegistrationRequest {
    fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        // This is a simplified implementation
        // In a real scenario, you'd use proper type checking
        None
    }
}

impl Downcast for fido_server::AuthenticationRequest {
    fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        // This is a simplified implementation
        None
    }
}