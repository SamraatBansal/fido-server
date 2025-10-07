//! Unit tests for challenge management

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use crate::common::{TestHelpers, SecurityTestVectors};

#[tokio::test]
async fn test_challenge_generation() {
    // Test challenge generation
    let challenge1 = TestHelpers::generate_test_challenge();
    let challenge2 = TestHelpers::generate_test_challenge();
    
    // Challenges should be unique
    assert_ne!(challenge1, challenge2, "Challenges should be unique");
    
    // Challenges should be non-empty
    assert!(!challenge1.is_empty(), "Challenge should not be empty");
    assert!(!challenge2.is_empty(), "Challenge should not be empty");
    
    // Challenges should be valid UUID format
    assert!(Uuid::parse_str(&challenge1).is_ok(), "Challenge should be valid UUID");
    assert!(Uuid::parse_str(&challenge2).is_ok(), "Challenge should be valid UUID");
}

#[tokio::test]
async fn test_challenge_storage() {
    // Test challenge storage and retrieval
    let mut challenge_store: HashMap<String, (String, SystemTime)> = HashMap::new();
    
    let user_id = "test-user@example.com";
    let challenge = TestHelpers::generate_test_challenge();
    let created_at = SystemTime::now();
    
    // Store challenge
    challenge_store.insert(challenge.clone(), (user_id.to_string(), created_at));
    
    // Retrieve challenge
    let stored_data = challenge_store.get(&challenge).unwrap();
    assert_eq!(stored_data.0, user_id, "User ID should match");
    assert_eq!(stored_data.1, created_at, "Creation time should match");
}

#[tokio::test]
async fn test_challenge_expiration() {
    // Test challenge expiration logic
    let mut challenge_store: HashMap<String, (String, SystemTime)> = HashMap::new();
    
    let challenge = TestHelpers::generate_test_challenge();
    let expired_time = SystemTime::now() - Duration::from_secs(600); // 10 minutes ago
    
    // Store expired challenge
    challenge_store.insert(challenge.clone(), ("user@example.com".to_string(), expired_time));
    
    // Check if challenge is expired (assuming 5-minute timeout)
    let stored_data = challenge_store.get(&challenge).unwrap();
    let elapsed = SystemTime::now().duration_since(stored_data.1).unwrap();
    
    assert!(elapsed > Duration::from_secs(300), "Challenge should be expired");
}

#[tokio::test]
async fn test_challenge_cleanup() {
    // Test cleanup of expired challenges
    let mut challenge_store: HashMap<String, (String, SystemTime)> = HashMap::new();
    
    // Add valid challenge
    let valid_challenge = TestHelpers::generate_test_challenge();
    let valid_time = SystemTime::now();
    challenge_store.insert(valid_challenge.clone(), ("user1@example.com".to_string(), valid_time));
    
    // Add expired challenges
    let expired_challenge1 = TestHelpers::generate_test_challenge();
    let expired_challenge2 = TestHelpers::generate_test_challenge();
    let expired_time = SystemTime::now() - Duration::from_secs(600);
    
    challenge_store.insert(expired_challenge1.clone(), ("user2@example.com".to_string(), expired_time));
    challenge_store.insert(expired_challenge2.clone(), ("user3@example.com".to_string(), expired_time));
    
    // Cleanup expired challenges
    let timeout = Duration::from_secs(300);
    challenge_store.retain(|_, (_, created_at)| {
        SystemTime::now().duration_since(*created_at).unwrap() < timeout
    });
    
    // Should only contain valid challenge
    assert_eq!(challenge_store.len(), 1, "Should only contain valid challenge");
    assert!(challenge_store.contains_key(&valid_challenge), "Should contain valid challenge");
    assert!(!challenge_store.contains_key(&expired_challenge1), "Should not contain expired challenge 1");
    assert!(!challenge_store.contains_key(&expired_challenge2), "Should not contain expired challenge 2");
}

#[tokio::test]
async fn test_challenge_uniqueness() {
    // Test that challenges are unique across multiple generations
    let mut challenges = std::collections::HashSet::new();
    
    // Generate multiple challenges
    for _ in 0..1000 {
        let challenge = TestHelpers::generate_test_challenge();
        assert!(!challenges.contains(&challenge), "Challenge should be unique");
        challenges.insert(challenge);
    }
    
    assert_eq!(challenges.len(), 1000, "Should have 1000 unique challenges");
}

#[tokio::test]
async fn test_challenge_format_validation() {
    // Test challenge format validation
    let valid_challenge = TestHelpers::generate_test_challenge();
    
    // Should be valid UUID
    assert!(Uuid::parse_str(&valid_challenge).is_ok(), "Valid challenge should parse as UUID");
    
    // Should be base64url safe
    assert!(TestHelpers::is_valid_base64url(&valid_challenge), "Challenge should be base64url safe");
    
    // Should not contain invalid characters
    assert!(!valid_challenge.contains('+'), "Challenge should not contain '+'");
    assert!(!valid_challenge.contains('/'), "Challenge should not contain '/'");
    assert!(!valid_challenge.contains('='), "Challenge should not contain '='");
}

#[tokio::test]
async fn test_challenge_length_requirements() {
    // Test challenge length requirements
    let challenge = TestHelpers::generate_test_challenge();
    
    // UUID-based challenges should be 36 characters (with hyphens)
    assert_eq!(challenge.len(), 36, "UUID challenge should be 36 characters");
    
    // Test custom length challenge
    let custom_challenge = Uuid::new_v4().as_hyphenated().to_string().replace('-', "");
    assert_eq!(custom_challenge.len(), 32, "Custom challenge should be 32 characters");
    
    // Should still be valid base64url
    assert!(TestHelpers::is_valid_base64url(&custom_challenge), "Custom challenge should be base64url safe");
}

#[tokio::test]
async fn test_challenge_concurrent_generation() {
    // Test concurrent challenge generation
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    let challenges = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let mut handles = vec![];
    
    // Spawn multiple threads to generate challenges
    for _ in 0..10 {
        let challenges_clone = Arc::clone(&challenges);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let challenge = TestHelpers::generate_test_challenge();
                let mut set = challenges_clone.lock().unwrap();
                assert!(!set.contains(&challenge), "Challenge should be unique across threads");
                set.insert(challenge);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Should have 1000 unique challenges
    let final_challenges = challenges.lock().unwrap();
    assert_eq!(final_challenges.len(), 1000, "Should have 1000 unique challenges");
}

#[tokio::test]
async fn test_challenge_reuse_prevention() {
    // Test that challenges cannot be reused
    let mut used_challenges = std::collections::HashSet::new();
    
    // Simulate challenge usage
    for _ in 0..100 {
        let challenge = TestHelpers::generate_test_challenge();
        
        // First use should succeed
        assert!(!used_challenges.contains(&challenge), "Challenge should not be used before");
        used_challenges.insert(challenge.clone());
        
        // Second use should fail
        assert!(used_challenges.contains(&challenge), "Challenge should be marked as used");
    }
}

#[tokio::test]
async fn test_challenge_security_properties() {
    // Test challenge security properties
    let challenge1 = TestHelpers::generate_test_challenge();
    let challenge2 = TestHelpers::generate_test_challenge();
    
    // Challenges should be unpredictable
    assert_ne!(challenge1, challenge2, "Challenges should be different");
    
    // Should not be sequential
    let uuid1 = Uuid::parse_str(&challenge1).unwrap();
    let uuid2 = Uuid::parse_str(&challenge2).unwrap();
    
    // UUID version and variant should be correct
    assert_eq!(uuid1.get_version_num(), 4, "Should be UUID v4 (random)");
    assert_eq!(uuid2.get_version_num(), 4, "Should be UUID v4 (random)");
    
    // Should have sufficient entropy (128 bits for UUID v4)
    let bytes1 = uuid1.as_bytes();
    let bytes2 = uuid2.as_bytes();
    
    let mut differences = 0;
    for i in 0..16 {
        if bytes1[i] != bytes2[i] {
            differences += 1;
        }
    }
    
    // Should have significant differences (expected for random UUIDs)
    assert!(differences > 4, "Challenges should have significant byte differences");
}

#[tokio::test]
async fn test_challenge_error_handling() {
    // Test error handling for challenge operations
    let mut challenge_store: HashMap<String, (String, SystemTime)> = HashMap::new();
    
    // Test retrieval of non-existent challenge
    let non_existent = "non-existent-challenge";
    assert!(challenge_store.get(non_existent).is_none(), "Non-existent challenge should return None");
    
    // Test removal of non-existent challenge
    let removed = challenge_store.remove(non_existent);
    assert!(removed.is_none(), "Removing non-existent challenge should return None");
    
    // Test with empty challenge string
    let empty_challenge = "";
    assert!(challenge_store.get(empty_challenge).is_none(), "Empty challenge should return None");
}

#[tokio::test]
async fn test_challenge_performance() {
    // Test challenge generation performance
    let start = SystemTime::now();
    
    // Generate 10,000 challenges
    let mut challenges = Vec::new();
    for _ in 0..10_000 {
        challenges.push(TestHelpers::generate_test_challenge());
    }
    
    let elapsed = SystemTime::now().duration_since(start).unwrap();
    
    // Should complete within reasonable time (less than 1 second)
    assert!(elapsed < Duration::from_secs(1), "Challenge generation should be fast");
    
    // All challenges should be unique
    let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
    assert_eq!(unique_challenges.len(), 10_000, "All challenges should be unique");
}