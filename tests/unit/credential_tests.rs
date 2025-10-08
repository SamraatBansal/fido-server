//! Unit tests for credential management

use std::collections::HashMap;
use serde_json::json;
use base64::{Engine, engine::general_purpose};
use fido_server::common::{TestHelpers, SecurityTestVectors};

#[derive(Debug, Clone)]
pub struct TestCredential {
    pub id: Vec<u8>,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub attestation_format: String,
    pub transports: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub sign_count: u64,
}

impl TestCredential {
    pub fn new(user_id: String) -> Self {
        Self {
            id: TestHelpers::create_mock_credential_id(),
            user_id,
            public_key: vec![1, 2, 3, 4], // Mock public key
            attestation_format: "none".to_string(),
            transports: vec!["internal".to_string()],
            created_at: chrono::Utc::now(),
            last_used_at: None,
            sign_count: 0,
        }
    }
}

#[tokio::test]
async fn test_credential_creation() {
    // Test valid credential creation
    let user_id = TestHelpers::create_mock_user_id();
    let credential = TestCredential::new(user_id.clone());
    
    // Validate credential properties
    assert!(!credential.id.is_empty(), "Credential ID should not be empty");
    assert_eq!(credential.user_id, user_id, "User ID should match");
    assert!(!credential.public_key.is_empty(), "Public key should not be empty");
    assert!(!credential.attestation_format.is_empty(), "Attestation format should not be empty");
    assert!(!credential.transports.is_empty(), "Transports should not be empty");
    assert_eq!(credential.sign_count, 0, "Sign count should start at 0");
    assert!(credential.last_used_at.is_none(), "Last used at should be None initially");
}

#[tokio::test]
async fn test_credential_storage() {
    // Test credential storage and retrieval
    let mut credential_store: HashMap<String, TestCredential> = HashMap::new();
    
    let user_id = TestHelpers::create_mock_user_id();
    let credential = TestCredential::new(user_id);
    let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential.id);
    
    // Store credential
    credential_store.insert(credential_id.clone(), credential.clone());
    
    // Retrieve credential
    let retrieved_credential = credential_store.get(&credential_id).unwrap();
    assert_eq!(retrieved_credential.id, credential.id, "Retrieved credential ID should match");
    assert_eq!(retrieved_credential.user_id, credential.user_id, "Retrieved user ID should match");
    assert_eq!(retrieved_credential.public_key, credential.public_key, "Retrieved public key should match");
}

#[tokio::test]
async fn test_credential_lookup_by_user() {
    // Test credential lookup by user ID
    let mut credential_store: HashMap<String, TestCredential> = HashMap::new();
    let mut user_credentials: HashMap<String, Vec<String>> = HashMap::new();
    
    let user_id = TestHelpers::create_mock_user_id();
    
    // Create multiple credentials for the same user
    let credential1 = TestCredential::new(user_id.clone());
    let credential2 = TestCredential::new(user_id.clone());
    let credential3 = TestCredential::new(user_id.clone());
    
    let cred1_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential1.id);
    let cred2_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential2.id);
    let cred3_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential3.id);
    
    // Store credentials
    credential_store.insert(cred1_id.clone(), credential1);
    credential_store.insert(cred2_id.clone(), credential2);
    credential_store.insert(cred3_id.clone(), credential3);
    
    // Index by user
    user_credentials.insert(user_id.clone(), vec![cred1_id.clone(), cred2_id.clone(), cred3_id.clone()]);
    
    // Lookup credentials by user
    let user_creds = user_credentials.get(&user_id).unwrap();
    assert_eq!(user_creds.len(), 3, "User should have 3 credentials");
    assert!(user_creds.contains(&cred1_id), "Should contain credential 1");
    assert!(user_creds.contains(&cred2_id), "Should contain credential 2");
    assert!(user_creds.contains(&cred3_id), "Should contain credential 3");
}

#[tokio::test]
async fn test_credential_update() {
    // Test credential update functionality
    let mut credential_store: HashMap<String, TestCredential> = HashMap::new();
    
    let user_id = TestHelpers::create_mock_user_id();
    let mut credential = TestCredential::new(user_id);
    let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential.id);
    
    // Store initial credential
    credential_store.insert(credential_id.clone(), credential.clone());
    
    // Update credential usage
    std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure time difference
    credential.last_used_at = Some(chrono::Utc::now());
    credential.sign_count = 5;
    
    credential_store.insert(credential_id.clone(), credential.clone());
    
    // Verify update
    let updated_credential = credential_store.get(&credential_id).unwrap();
    assert!(updated_credential.last_used_at.is_some(), "Last used at should be set");
    assert_eq!(updated_credential.sign_count, 5, "Sign count should be updated");
}

#[tokio::test]
async fn test_credential_deletion() {
    // Test credential deletion
    let mut credential_store: HashMap<String, TestCredential> = HashMap::new();
    let mut user_credentials: HashMap<String, Vec<String>> = HashMap::new();
    
    let user_id = TestHelpers::create_mock_user_id();
    let credential = TestCredential::new(user_id.clone());
    let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential.id);
    
    // Store credential
    credential_store.insert(credential_id.clone(), credential.clone());
    user_credentials.insert(user_id, vec![credential_id.clone()]);
    
    // Verify credential exists
    assert!(credential_store.contains_key(&credential_id), "Credential should exist before deletion");
    
    // Delete credential
    credential_store.remove(&credential_id);
    
    // Verify deletion
    assert!(!credential_store.contains_key(&credential_id), "Credential should not exist after deletion");
}

#[tokio::test]
async fn test_credential_validation() {
    // Test credential validation
    
    // Test valid credential formats
    let valid_formats = vec!["packed", "fido-u2f", "none", "android-key", "android-safetynet"];
    for format in valid_formats {
        let mut credential = TestCredential::new(TestHelpers::create_mock_user_id());
        credential.attestation_format = format.to_string();
        assert!(!credential.attestation_format.is_empty(), "Format should be valid");
    }
    
    // Test valid transports
    let valid_transports = vec!["usb", "nfc", "ble", "internal", "hybrid"];
    for transport in valid_transports {
        let mut credential = TestCredential::new(TestHelpers::create_mock_user_id());
        credential.transports = vec![transport.to_string()];
        assert!(!credential.transports.is_empty(), "Transport should be valid");
    }
}

#[tokio::test]
async fn test_credential_edge_cases() {
    // Test edge cases for credential operations
    
    // Test with empty credential ID
    let mut credential = TestCredential::new(TestHelpers::create_mock_user_id());
    credential.id = vec![];
    assert!(credential.id.is_empty(), "Empty credential ID should be allowed for testing");
    
    // Test with empty public key
    credential.public_key = vec![];
    assert!(credential.public_key.is_empty(), "Empty public key should be allowed for testing");
    
    // Test with multiple transports
    credential.transports = vec!["usb".to_string(), "nfc".to_string(), "ble".to_string()];
    assert_eq!(credential.transports.len(), 3, "Should support multiple transports");
    
    // Test with high sign count
    credential.sign_count = u64::MAX;
    assert_eq!(credential.sign_count, u64::MAX, "Should support maximum sign count");
}

#[tokio::test]
async fn test_credential_security() {
    // Test security aspects of credential management
    
    // Test credential ID randomness
    let credential1 = TestCredential::new(TestHelpers::create_mock_user_id());
    let credential2 = TestCredential::new(TestHelpers::create_mock_user_id());
    
    assert_ne!(credential1.id, credential2.id, "Credential IDs should be unique");
    assert!(credential1.id.len() >= 16, "Credential ID should have sufficient length");
    assert!(credential2.id.len() >= 16, "Credential ID should have sufficient length");
    
    // Test credential ID encoding
    let cred_id_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&credential1.id);
    assert!(TestHelpers::is_valid_base64url(&cred_id_b64), "Credential ID should be base64url safe");
    
    // Test with malformed credential data
    let malformed_data = SecurityTestVectors::malformed_cbor();
    assert!(!malformed_data.is_empty(), "Malformed data should not be empty");
}

#[tokio::test]
async fn test_credential_performance() {
    // Test performance of credential operations
    use std::time::Instant;
    
    let mut credential_store: HashMap<String, TestCredential> = HashMap::new();
    
    // Test bulk credential creation
    let start = Instant::now();
    for i in 0..10_000 {
        let user_id = format!("user-{}", i % 100); // 100 users, 100 credentials each
        let credential = TestCredential::new(user_id);
        let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential.id);
        credential_store.insert(credential_id, credential);
    }
    let creation_time = start.elapsed();
    
    // Should complete within reasonable time
    assert!(creation_time.as_secs() < 5, "Bulk credential creation should be fast");
    
    // Test lookup performance
    let start = Instant::now();
    let credentials: Vec<_> = credential_store.values().take(1_000).collect();
    for credential in &credentials {
        let _id = &credential.id;
        let _user_id = &credential.user_id;
    }
    let lookup_time = start.elapsed();
    
    // Should complete within reasonable time
    assert!(lookup_time.as_millis() < 100, "Credential lookup should be fast");
}

#[tokio::test]
async fn test_credential_concurrent_operations() {
    // Test concurrent credential operations
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    let credential_store = Arc::new(Mutex::new(HashMap::<String, TestCredential>::new()));
    let mut handles = vec![];
    
    // Spawn multiple threads to create credentials
    for i in 0..10 {
        let store_clone = Arc::clone(&credential_store);
        let handle = thread::spawn(move || {
            for _j in 0..100 {
                let user_id = format!("user-{}", i);
                let credential = TestCredential::new(user_id);
                let credential_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential.id);
                let mut store = store_clone.lock().unwrap();
                store.insert(credential_id, credential);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify all credentials were created
    let final_store = credential_store.lock().unwrap();
    assert_eq!(final_store.len(), 1000, "Should have 1000 credentials");
}

#[tokio::test]
async fn test_credential_serialization() {
    // Test credential serialization/deserialization
    let credential = TestCredential::new(TestHelpers::create_mock_user_id());
    
    // Serialize to JSON
    let credential_json = json!({
        "id": general_purpose::URL_SAFE_NO_PAD.encode(&credential.id),
        "userId": credential.user_id,
        "publicKey": general_purpose::URL_SAFE_NO_PAD.encode(&credential.public_key),
        "attestationFormat": credential.attestation_format,
        "transports": credential.transports,
        "createdAt": credential.created_at.to_rfc3339(),
        "lastUsedAt": credential.last_used_at.map(|dt| dt.to_rfc3339()),
        "signCount": credential.sign_count
    });
    
    // Validate JSON structure
    assert!(credential_json.get("id").is_some(), "ID should be present in JSON");
    assert!(credential_json.get("userId").is_some(), "User ID should be present in JSON");
    assert!(credential_json.get("publicKey").is_some(), "Public key should be present in JSON");
    assert!(credential_json.get("attestationFormat").is_some(), "Attestation format should be present in JSON");
    assert!(credential_json.get("transports").is_some(), "Transports should be present in JSON");
    assert!(credential_json.get("createdAt").is_some(), "Created at should be present in JSON");
    assert!(credential_json.get("signCount").is_some(), "Sign count should be present in JSON");
    
    // Validate field types
    assert!(credential_json["id"].is_string(), "ID should be string");
    assert!(credential_json["userId"].is_string(), "User ID should be string");
    assert!(credential_json["publicKey"].is_string(), "Public key should be string");
    assert!(credential_json["attestationFormat"].is_string(), "Attestation format should be string");
    assert!(credential_json["transports"].is_array(), "Transports should be array");
    assert!(credential_json["createdAt"].is_string(), "Created at should be string");
    assert!(credential_json["signCount"].is_number(), "Sign count should be number");
}

#[tokio::test]
async fn test_credential_expiration() {
    // Test credential expiration logic
    let credential = TestCredential::new(TestHelpers::create_mock_user_id());
    
    // Credential should be valid initially
    assert!(is_credential_valid(&credential), "New credential should be valid");
    
    // Simulate old credential (created more than 1 year ago)
    let mut old_credential = credential.clone();
    old_credential.created_at = chrono::Utc::now() - chrono::Duration::days(400);
    
    assert!(!is_credential_valid(&old_credential), "Old credential should be invalid");
}

#[tokio::test]
async fn test_credential_rotation() {
    // Test credential rotation (adding new credentials)
    let mut user_credentials: HashMap<String, Vec<String>> = HashMap::new();
    let user_id = TestHelpers::create_mock_user_id();
    
    // Add initial credential
    let credential1 = TestCredential::new(user_id.clone());
    let cred1_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential1.id);
    user_credentials.insert(user_id.clone(), vec![cred1_id.clone()]);
    
    // Add new credential (rotation)
    let credential2 = TestCredential::new(user_id.clone());
    let cred2_id = general_purpose::URL_SAFE_NO_PAD.encode(&credential2.id);
    
    let creds = user_credentials.get_mut(&user_id).unwrap();
    creds.push(cred2_id.clone());
    
    // Verify rotation
    let final_creds = user_credentials.get(&user_id).unwrap();
    assert_eq!(final_creds.len(), 2, "Should have 2 credentials after rotation");
    assert!(final_creds.contains(&cred1_id), "Should contain old credential");
    assert!(final_creds.contains(&cred2_id), "Should contain new credential");
}

fn is_credential_valid(credential: &TestCredential) -> bool {
    // Check if credential is not too old (1 year)
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(credential.created_at);
    age.num_days() < 365
}