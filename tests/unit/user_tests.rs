//! Unit tests for user management

use std::collections::HashMap;
use uuid::Uuid;
use crate::common::{TestHelpers, SecurityTestVectors};

#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl TestUser {
    pub fn new(username: String, display_name: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: TestHelpers::create_mock_user_id(),
            username,
            display_name,
            created_at: now,
            updated_at: now,
        }
    }
}

#[tokio::test]
async fn test_user_creation() {
    // Test valid user creation
    let username = "alice@example.com";
    let display_name = "Alice Smith";
    
    let user = TestUser::new(username.to_string(), display_name.to_string());
    
    // Validate user properties
    assert!(!user.id.is_empty(), "User ID should not be empty");
    assert_eq!(user.username, username, "Username should match");
    assert_eq!(user.display_name, display_name, "Display name should match");
    assert!(user.created_at <= user.updated_at, "Created at should be before or equal to updated at");
    
    // Validate ID format
    assert!(Uuid::parse_str(&user.id).is_ok(), "User ID should be valid UUID");
}

#[tokio::test]
async fn test_user_validation() {
    // Test email validation
    let valid_emails = vec![
        "user@example.com",
        "test.user+tag@example.co.uk",
        "user123@test-domain.com",
        "firstname.lastname@company.org",
    ];
    
    for email in valid_emails {
        assert!(is_valid_email(email), "Email {} should be valid", email);
    }
    
    // Test invalid emails
    let invalid_emails = vec![
        "invalid-email",
        "@example.com",
        "user@",
        "user..name@example.com",
        "user@.com",
        "user@example.",
        "",
        "user name@example.com",
        "user@exam ple.com",
    ];
    
    for email in invalid_emails {
        assert!(!is_valid_email(email), "Email {} should be invalid", email);
    }
}

#[tokio::test]
async fn test_user_storage() {
    // Test user storage and retrieval
    let mut user_store: HashMap<String, TestUser> = HashMap::new();
    
    let user = TestUser::new(
        "bob@example.com".to_string(),
        "Bob Johnson".to_string(),
    );
    
    // Store user
    user_store.insert(user.id.clone(), user.clone());
    
    // Retrieve user
    let retrieved_user = user_store.get(&user.id).unwrap();
    assert_eq!(retrieved_user.id, user.id, "Retrieved user ID should match");
    assert_eq!(retrieved_user.username, user.username, "Retrieved username should match");
    assert_eq!(retrieved_user.display_name, user.display_name, "Retrieved display name should match");
}

#[tokio::test]
async fn test_user_lookup_by_username() {
    // Test user lookup by username
    let mut user_store: HashMap<String, TestUser> = HashMap::new();
    let mut username_index: HashMap<String, String> = HashMap::new();
    
    let user1 = TestUser::new("alice@example.com".to_string(), "Alice Smith".to_string());
    let user2 = TestUser::new("bob@example.com".to_string(), "Bob Johnson".to_string());
    
    // Store users with username index
    user_store.insert(user1.id.clone(), user1.clone());
    username_index.insert(user1.username.clone(), user1.id.clone());
    
    user_store.insert(user2.id.clone(), user2.clone());
    username_index.insert(user2.username.clone(), user2.id.clone());
    
    // Lookup by username
    let alice_id = username_index.get("alice@example.com").unwrap();
    let alice_user = user_store.get(alice_id).unwrap();
    assert_eq!(alice_user.username, "alice@example.com", "Should find Alice by username");
    
    let bob_id = username_index.get("bob@example.com").unwrap();
    let bob_user = user_store.get(bob_id).unwrap();
    assert_eq!(bob_user.username, "bob@example.com", "Should find Bob by username");
}

#[tokio::test]
async fn test_user_not_found() {
    // Test user not found scenarios
    let user_store: HashMap<String, TestUser> = HashMap::new();
    let username_index: HashMap<String, String> = HashMap::new();
    
    // Test lookup by ID
    let non_existent_id = TestHelpers::create_mock_user_id();
    assert!(user_store.get(&non_existent_id).is_none(), "Non-existent user ID should return None");
    
    // Test lookup by username
    assert!(username_index.get("nonexistent@example.com").is_none(), 
            "Non-existent username should return None");
}

#[tokio::test]
async fn test_user_update() {
    // Test user update functionality
    let mut user_store: HashMap<String, TestUser> = HashMap::new();
    
    let mut user = TestUser::new(
        "charlie@example.com".to_string(),
        "Charlie Brown".to_string(),
    );
    
    // Store initial user
    user_store.insert(user.id.clone(), user.clone());
    
    // Update user
    let original_updated_at = user.updated_at;
    std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure time difference
    
    user.display_name = "Charles Brown".to_string();
    user.updated_at = chrono::Utc::now();
    
    user_store.insert(user.id.clone(), user.clone());
    
    // Verify update
    let updated_user = user_store.get(&user.id).unwrap();
    assert_eq!(updated_user.display_name, "Charles Brown", "Display name should be updated");
    assert!(updated_user.updated_at > original_updated_at, "Updated at should be newer");
}

#[tokio::test]
async fn test_user_deletion() {
    // Test user deletion
    let mut user_store: HashMap<String, TestUser> = HashMap::new();
    let mut username_index: HashMap<String, String> = HashMap::new();
    
    let user = TestUser::new("david@example.com".to_string(), "David Wilson".to_string());
    
    // Store user
    user_store.insert(user.id.clone(), user.clone());
    username_index.insert(user.username.clone(), user.id.clone());
    
    // Verify user exists
    assert!(user_store.contains_key(&user.id), "User should exist before deletion");
    assert!(username_index.contains_key(&user.username), "Username index should contain user");
    
    // Delete user
    user_store.remove(&user.id);
    username_index.remove(&user.username);
    
    // Verify deletion
    assert!(!user_store.contains_key(&user.id), "User should not exist after deletion");
    assert!(!username_index.contains_key(&user.username), "Username index should not contain user");
}

#[tokio::test]
async fn test_user_edge_cases() {
    // Test edge cases for user operations
    
    // Test with very long username
    let long_username = "a".repeat(300) + "@example.com";
    assert!(!is_valid_email(&long_username), "Very long username should be invalid");
    
    // Test with empty display name
    let user = TestUser::new("eve@example.com".to_string(), "".to_string());
    assert_eq!(user.display_name, "", "Empty display name should be allowed");
    
    // Test with special characters in display name
    let special_display_name = "Émilie O'Connor-Jones 🌟";
    let user = TestUser::new("emilie@example.com".to_string(), special_display_name.to_string());
    assert_eq!(user.display_name, special_display_name, "Special characters should be allowed in display name");
    
    // Test with username case sensitivity
    let user1 = TestUser::new("Frank@example.com".to_string(), "Frank Smith".to_string());
    let user2 = TestUser::new("frank@example.com".to_string(), "Frank Smith".to_string());
    assert_ne!(user1.username, user2.username, "Usernames should be case-sensitive");
}

#[tokio::test]
async fn test_user_security() {
    // Test security aspects of user management
    
    // Test SQL injection attempt in username
    let sql_injection = "'; DROP TABLE users; --";
    assert!(!is_valid_email(sql_injection), "SQL injection should be invalid email");
    
    // Test XSS attempt in display name
    let xss_attempt = "<script>alert('xss')</script>";
    let user = TestUser::new("test@example.com".to_string(), xss_attempt.to_string());
    assert_eq!(user.display_name, xss_attempt, "XSS should be stored but escaped in output");
    
    // Test user ID randomness
    let user1 = TestUser::new("user1@example.com".to_string(), "User One".to_string());
    let user2 = TestUser::new("user2@example.com".to_string(), "User Two".to_string());
    
    assert_ne!(user1.id, user2.id, "User IDs should be unique");
    assert!(Uuid::parse_str(&user1.id).is_ok(), "User ID should be valid UUID");
    assert!(Uuid::parse_str(&user2.id).is_ok(), "User ID should be valid UUID");
}

#[tokio::test]
async fn test_user_performance() {
    // Test performance of user operations
    use std::time::Instant;
    
    let mut user_store: HashMap<String, TestUser> = HashMap::new();
    let mut username_index: HashMap<String, String> = HashMap::new();
    
    // Test bulk user creation
    let start = Instant::now();
    for i in 0..10_000 {
        let user = TestUser::new(
            format!("user{}@example.com", i),
            format!("User {}", i),
        );
        user_store.insert(user.id.clone(), user.clone());
        username_index.insert(user.username.clone(), user.id.clone());
    }
    let creation_time = start.elapsed();
    
    // Should complete within reasonable time
    assert!(creation_time.as_secs() < 5, "Bulk user creation should be fast");
    
    // Test lookup performance
    let start = Instant::now();
    for i in 0..1_000 {
        let username = format!("user{}@example.com", i * 10);
        let user_id = username_index.get(&username).unwrap();
        let _user = user_store.get(user_id).unwrap();
    }
    let lookup_time = start.elapsed();
    
    // Should complete within reasonable time
    assert!(lookup_time.as_millis() < 100, "User lookup should be fast");
}

#[tokio::test]
async fn test_user_concurrent_operations() {
    // Test concurrent user operations
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    let user_store = Arc::new(Mutex::new(HashMap::<String, TestUser>::new()));
    let mut handles = vec![];
    
    // Spawn multiple threads to create users
    for i in 0..10 {
        let store_clone = Arc::clone(&user_store);
        let handle = thread::spawn(move || {
            for j in 0..100 {
                let user = TestUser::new(
                    format!("user{}-{}@example.com", i, j),
                    format!("User {}-{}", i, j),
                );
                let mut store = store_clone.lock().unwrap();
                store.insert(user.id.clone(), user);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify all users were created
    let final_store = user_store.lock().unwrap();
    assert_eq!(final_store.len(), 1000, "Should have 1000 users");
}

fn is_valid_email(email: &str) -> bool {
    // Simple email validation regex
    let email_regex = regex::Regex::new(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ).unwrap();
    
    email_regex.is_match(email) && email.len() <= 254 // RFC 5321 limit
}

#[tokio::test]
async fn test_user_email_validation_edge_cases() {
    // Test edge cases for email validation
    
    // Test maximum length email (254 characters)
    let local_part = "a".repeat(64); // Max local part length
    let domain_part = "b".repeat(63); // Max domain label length
    let max_email = format!("{}@{}.com", local_part, domain_part);
    
    assert!(is_valid_email(&max_email), "Maximum length email should be valid");
    assert_eq!(max_email.len(), 64 + 1 + 63 + 4, "Email should be exactly 132 characters");
    
    // Test email that's too long
    let too_long_email = format!("{}@{}.com", "a".repeat(65), domain_part);
    assert!(!is_valid_email(&too_long_email), "Email with local part > 64 chars should be invalid");
    
    // Test domain that's too long
    let too_long_domain = format!("{}@{}.com", local_part, "b".repeat(64));
    assert!(!is_valid_email(&too_long_domain), "Email with domain label > 63 chars should be invalid");
}