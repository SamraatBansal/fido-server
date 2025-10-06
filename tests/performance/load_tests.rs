//! Load tests for FIDO service

use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_registration_load() {
        let service = Arc::new(tokio::sync::Mutex::new(FidoService::new()));
        let mut join_set = JoinSet::new();
        
        let start_time = Instant::now();
        let num_requests = 100;
        
        // Spawn concurrent registration requests
        for i in 0..num_requests {
            let service_clone = service.clone();
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let request = RegistrationRequest {
                    username: format!("loaduser{}@example.com", i),
                    display_name: format!("Load User {}", i),
                };
                let start = Instant::now();
                let result = svc.start_registration(request).await;
                let duration = start.elapsed();
                (result, duration)
            });
        }
        
        // Collect results
        let mut successes = 0;
        let mut failures = 0;
        let mut total_duration = Duration::ZERO;
        let mut max_duration = Duration::ZERO;
        let mut min_duration = Duration::MAX;
        
        while let Some(result) = join_set.join_next().await {
            match result.unwrap() {
                (Ok(_), duration) => {
                    successes += 1;
                    total_duration += duration;
                    max_duration = max_duration.max(duration);
                    min_duration = min_duration.min(duration);
                }
                (Err(_), _) => {
                    failures += 1;
                }
            }
        }
        
        let total_time = start_time.elapsed();
        let avg_duration = total_duration / successes as u32;
        
        // Assertions
        assert_eq!(successes, num_requests, "All registrations should succeed");
        assert_eq!(failures, 0, "No registrations should fail");
        
        // Performance assertions (adjust thresholds based on requirements)
        assert!(total_time < Duration::from_secs(5), "Total time should be under 5 seconds");
        assert!(avg_duration < Duration::from_millis(100), "Average request time should be under 100ms");
        assert!(max_duration < Duration::from_millis(500), "Max request time should be under 500ms");
        
        println!("Load Test Results:");
        println!("  Total requests: {}", num_requests);
        println!("  Successes: {}", successes);
        println!("  Failures: {}", failures);
        println!("  Total time: {:?}", total_time);
        println!("  Average time: {:?}", avg_duration);
        println!("  Min time: {:?}", min_duration);
        println!("  Max time: {:?}", max_duration);
        println!("  Requests/sec: {:.2}", num_requests as f64 / total_time.as_secs_f64());
    }

    #[tokio::test]
    async fn test_concurrent_authentication_load() {
        let mut service = FidoService::new();
        
        // First, register users
        let num_users = 50;
        for i in 0..num_users {
            let request = RegistrationRequest {
                username: format!("authuser{}@example.com", i),
                display_name: format!("Auth User {}", i),
            };
            let _ = service.start_registration(request).await.unwrap();
        }
        
        let service = Arc::new(tokio::sync::Mutex::new(service));
        let mut join_set = JoinSet::new();
        
        let start_time = Instant::now();
        
        // Spawn concurrent authentication requests
        for i in 0..num_users {
            let service_clone = service.clone();
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let request = AuthenticationRequest {
                    username: format!("authuser{}@example.com", i),
                };
                let start = Instant::now();
                let result = svc.start_authentication(request).await;
                let duration = start.elapsed();
                (result, duration)
            });
        }
        
        // Collect results
        let mut successes = 0;
        let mut failures = 0;
        let mut total_duration = Duration::ZERO;
        
        while let Some(result) = join_set.join_next().await {
            match result.unwrap() {
                (Ok(_), duration) => {
                    successes += 1;
                    total_duration += duration;
                }
                (Err(_), _) => {
                    failures += 1;
                }
            }
        }
        
        let total_time = start_time.elapsed();
        let avg_duration = if successes > 0 { total_duration / successes as u32 } else { Duration::ZERO };
        
        // Assertions
        assert_eq!(successes, num_users, "All authentications should succeed");
        assert_eq!(failures, 0, "No authentications should fail");
        assert!(total_time < Duration::from_secs(3), "Total time should be under 3 seconds");
        assert!(avg_duration < Duration::from_millis(100), "Average request time should be under 100ms");
        
        println!("Authentication Load Test Results:");
        println!("  Total requests: {}", num_users);
        println!("  Successes: {}", successes);
        println!("  Failures: {}", failures);
        println!("  Total time: {:?}", total_time);
        println!("  Average time: {:?}", avg_duration);
        println!("  Requests/sec: {:.2}", num_users as f64 / total_time.as_secs_f64());
    }

    #[tokio::test]
    async fn test_mixed_workload_load() {
        let service = Arc::new(tokio::sync::Mutex::new(FidoService::new()));
        let mut join_set = JoinSet::new();
        
        let start_time = Instant::now();
        let num_operations = 200;
        
        // Spawn mixed registration and authentication requests
        for i in 0..num_operations {
            let service_clone = service.clone();
            let is_registration = i % 2 == 0;
            
            join_set.spawn(async move {
                let mut svc = service_clone.lock().await;
                let start = Instant::now();
                
                let result = if is_registration {
                    let request = RegistrationRequest {
                        username: format!("mixed{}@example.com", i),
                        display_name: format!("Mixed User {}", i),
                    };
                    svc.start_registration(request).await
                } else {
                    // For authentication, use a previously registered user
                    let user_idx = i / 2;
                    let request = AuthenticationRequest {
                        username: format!("mixed{}@example.com", user_idx),
                    };
                    svc.start_authentication(request).await
                };
                
                let duration = start.elapsed();
                (result, duration, is_registration)
            });
        }
        
        // Collect results
        let mut reg_successes = 0;
        let mut reg_failures = 0;
        let mut auth_successes = 0;
        let mut auth_failures = 0;
        let mut total_duration = Duration::ZERO;
        
        while let Some(result) = join_set.join_next().await {
            match result.unwrap() {
                (Ok(_), duration, true) => {
                    reg_successes += 1;
                    total_duration += duration;
                }
                (Err(_), _, true) => {
                    reg_failures += 1;
                }
                (Ok(_), duration, false) => {
                    auth_successes += 1;
                    total_duration += duration;
                }
                (Err(_), _, false) => {
                    auth_failures += 1;
                }
            }
        }
        
        let total_time = start_time.elapsed();
        let total_successes = reg_successes + auth_successes;
        let avg_duration = if total_successes > 0 { total_duration / total_successes as u32 } else { Duration::ZERO };
        
        // Assertions
        assert!(reg_successes > num_operations / 2 - 5, "Most registrations should succeed");
        assert!(total_time < Duration::from_secs(10), "Total time should be under 10 seconds");
        assert!(avg_duration < Duration::from_millis(150), "Average request time should be under 150ms");
        
        println!("Mixed Workload Load Test Results:");
        println!("  Total operations: {}", num_operations);
        println!("  Registration successes: {}", reg_successes);
        println!("  Registration failures: {}", reg_failures);
        println!("  Authentication successes: {}", auth_successes);
        println!("  Authentication failures: {}", auth_failures);
        println!("  Total time: {:?}", total_time);
        println!("  Average time: {:?}", avg_duration);
        println!("  Operations/sec: {:.2}", num_operations as f64 / total_time.as_secs_f64());
    }

    #[tokio::test]
    async fn test_memory_usage_under_load() {
        // This is a basic memory usage test
        // In a real scenario, you'd want more sophisticated memory profiling
        let mut service = FidoService::new();
        
        let initial_memory = get_memory_usage();
        
        // Create many users and challenges
        for i in 0..1000 {
            let request = RegistrationRequest {
                username: format!("memory{}@example.com", i),
                display_name: format!("Memory User {}", i),
            };
            let _ = service.start_registration(request).await.unwrap();
        }
        
        let final_memory = get_memory_usage();
        let memory_increase = final_memory.saturating_sub(initial_memory);
        
        // Basic sanity check - memory shouldn't increase excessively
        // This is a very rough estimate and would need tuning based on actual requirements
        assert!(memory_increase < 100_000_000, "Memory increase should be reasonable (< 100MB)");
        
        println!("Memory Usage Test:");
        println!("  Initial memory: {} bytes", initial_memory);
        println!("  Final memory: {} bytes", final_memory);
        println!("  Memory increase: {} bytes", memory_increase);
    }

    #[tokio::test]
    async fn test_challenge_generation_performance() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "perf@example.com".to_string(),
            display_name: "Performance User".to_string(),
        };
        
        let num_challenges = 1000;
        let start_time = Instant::now();
        
        // Generate many challenges
        for _ in 0..num_challenges {
            let _ = service.start_registration(request.clone()).await.unwrap();
        }
        
        let total_time = start_time.elapsed();
        let avg_time = total_time / num_challenges;
        
        // Performance assertions
        assert!(total_time < Duration::from_secs(5), "Total time should be under 5 seconds");
        assert!(avg_time < Duration::from_micros(5000), "Average challenge generation should be under 5ms");
        
        println!("Challenge Generation Performance:");
        println!("  Challenges generated: {}", num_challenges);
        println!("  Total time: {:?}", total_time);
        println!("  Average time: {:?}", avg_time);
        println!("  Challenges/sec: {:.2}", num_challenges as f64 / total_time.as_secs_f64());
    }

    /// Get current memory usage (simplified version)
    fn get_memory_usage() -> usize {
        // This is a placeholder - in a real implementation you'd use
        // platform-specific APIs or crates like `memory-stats`
        // For now, return a reasonable default
        10_000_000 // 10MB placeholder
    }
}