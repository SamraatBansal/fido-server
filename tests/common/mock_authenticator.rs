//! Mock authenticator implementations for testing

use std::collections::HashMap;

/// Mock authenticator for testing WebAuthn flows
pub struct MockAuthenticator {
    pub credentials: HashMap<String, MockCredential>,
}

/// Mock credential data
pub struct MockCredential {
    pub id: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub counter: u32,
    pub user_id: String,
}

impl MockAuthenticator {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }
    
    /// Add a mock credential
    pub fn add_credential(&mut self, credential: MockCredential) {
        self.credentials.insert(credential.id.clone(), credential);
    }
    
    /// Get a credential by ID
    pub fn get_credential(&self, id: &str) -> Option<&MockCredential> {
        self.credentials.get(id)
    }
    
    /// Generate a mock attestation response
    pub fn create_attestation(&self, challenge: &str, user_id: &str) -> String {
        // This would normally create a real attestation object
        // For testing, we return a mock base64url-encoded value
        format!("mock-attestation-{}-{}", challenge, user_id)
    }
    
    /// Generate a mock assertion response
    pub fn create_assertion(&self, challenge: &str, credential_id: &str) -> String {
        // This would normally create a real assertion
        // For testing, we return a mock base64url-encoded value
        format!("mock-assertion-{}-{}", challenge, credential_id)
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}