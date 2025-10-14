//! Mock authenticator for generating realistic test data
//!
//! This module provides a mock authenticator that can generate realistic
//! attestation and assertion responses for testing purposes.

use serde_json::{json, Value};
use super::base64url;
use rand::{Rng, thread_rng};
use std::collections::HashMap;

/// Mock authenticator for generating test responses
pub struct MockAuthenticator {
    /// Private key for signing (mock)
    private_key: Vec<u8>,
    /// Credential counter
    counter: u32,
    /// Stored credentials
    credentials: HashMap<String, MockCredential>,
}

/// Mock credential data
#[derive(Clone)]
pub struct MockCredential {
    pub id: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub user_id: String,
    pub counter: u32,
}

impl MockAuthenticator {
    /// Create a new mock authenticator
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let private_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        Self {
            private_key,
            counter: 0,
            credentials: HashMap::new(),
        }
    }
    
    /// Generate a mock attestation response
    pub fn create_attestation_response(&mut self, challenge: &str, rp_id: &str, user_id: &str) -> Value {
        let credential_id = self.generate_credential_id();
        let client_data_json = self.create_client_data_json("webauthn.create", challenge, "https://example.com");
        let attestation_object = self.create_attestation_object(rp_id, &credential_id);
        
        // Store the credential
        let credential = MockCredential {
            id: credential_id.clone(),
            public_key: self.generate_public_key(),
            private_key: self.private_key.clone(),
            user_id: user_id.to_string(),
            counter: 0,
        };
        self.credentials.insert(credential_id.clone(), credential);
        
        json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "clientDataJSON": client_data_json,
                "attestationObject": attestation_object
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        })
    }
    
    /// Generate a mock assertion response
    pub fn create_assertion_response(&mut self, challenge: &str, credential_id: &str) -> Result<Value, String> {
        let credential = self.credentials.get_mut(credential_id)
            .ok_or_else(|| "Credential not found".to_string())?;
        
        credential.counter += 1;
        
        let client_data_json = self.create_client_data_json("webauthn.get", challenge, "https://example.com");
        let authenticator_data = self.create_authenticator_data("example.com", credential.counter);
        let signature = self.create_signature(&authenticator_data, &client_data_json);
        
        Ok(json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "authenticatorData": authenticator_data,
                "clientDataJSON": client_data_json,
                "signature": signature,
                "userHandle": base64url::encode(credential.user_id.as_bytes())
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
    }
    
    /// Create client data JSON
    fn create_client_data_json(&self, type_field: &str, challenge: &str, origin: &str) -> String {
        let client_data = json!({
            "type": type_field,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        });
        base64url::encode(client_data.to_string().as_bytes())
    }
    
    /// Create mock attestation object
    fn create_attestation_object(&self, rp_id: &str, credential_id: &str) -> String {
        let auth_data = self.create_auth_data_with_attested_cred(rp_id, credential_id);
        
        // Simplified CBOR-like structure (in reality this would be proper CBOR)
        let attestation_object = json!({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data
        });
        
        base64url::encode(attestation_object.to_string().as_bytes())
    }
    
    /// Create authenticator data with attested credential
    fn create_auth_data_with_attested_cred(&self, rp_id: &str, credential_id: &str) -> String {
        let mut auth_data = Vec::new();
        
        // RP ID hash (32 bytes)
        let rp_id_hash = self.hash_rp_id(rp_id);
        auth_data.extend_from_slice(&rp_id_hash);
        
        // Flags (1 byte) - User Present (0x01) + Attested Credential Data (0x40)
        auth_data.push(0x41);
        
        // Counter (4 bytes)
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        
        // Attested credential data
        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0u8; 16]);
        
        // Credential ID length (2 bytes)
        let cred_id_bytes = base64url::decode(credential_id).unwrap_or_default();
        auth_data.extend_from_slice(&(cred_id_bytes.len() as u16).to_be_bytes());
        
        // Credential ID
        auth_data.extend_from_slice(&cred_id_bytes);
        
        // Public key (simplified COSE format)
        let public_key = self.generate_public_key();
        auth_data.extend_from_slice(&public_key);
        
        base64url::encode(&auth_data)
    }
    
    /// Create authenticator data for assertion
    fn create_authenticator_data(&self, rp_id: &str, counter: u32) -> String {
        let mut auth_data = Vec::new();
        
        // RP ID hash (32 bytes)
        let rp_id_hash = self.hash_rp_id(rp_id);
        auth_data.extend_from_slice(&rp_id_hash);
        
        // Flags (1 byte) - User Present (0x01)
        auth_data.push(0x01);
        
        // Counter (4 bytes)
        auth_data.extend_from_slice(&counter.to_be_bytes());
        
        base64url::encode(&auth_data)
    }
    
    /// Create mock signature
    fn create_signature(&self, authenticator_data: &str, client_data_json: &str) -> String {
        // In a real implementation, this would create an actual signature
        // For testing, we create a deterministic mock signature
        let auth_data_bytes = base64url::decode(authenticator_data).unwrap_or_default();
        let client_data_bytes = base64url::decode(client_data_json).unwrap_or_default();
        
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&auth_data_bytes);
        signature_data.extend_from_slice(&self.hash_client_data(&client_data_bytes));
        
        // Mock signature (64 bytes for ES256)
        let mut signature = vec![0u8; 64];
        for (i, byte) in signature_data.iter().enumerate() {
            if i < 64 {
                signature[i] = *byte;
            }
        }
        
        base64url::encode(&signature)
    }
    
    /// Generate a credential ID
    fn generate_credential_id(&self) -> String {
        let mut rng = thread_rng();
        let id_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        base64url::encode(&id_bytes)
    }
    
    /// Generate a mock public key
    fn generate_public_key(&self) -> Vec<u8> {
        // Simplified COSE key format for ES256
        let mut public_key = Vec::new();
        
        // COSE key parameters (simplified)
        public_key.extend_from_slice(&[
            0x01, 0x02, // kty: EC2
            0x03, 0x26, // alg: ES256 (-7)
        ]);
        
        // X coordinate (32 bytes)
        let mut rng = thread_rng();
        let x_coord: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        public_key.extend_from_slice(&x_coord);
        
        // Y coordinate (32 bytes)
        let y_coord: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        public_key.extend_from_slice(&y_coord);
        
        public_key
    }
    
    /// Hash RP ID (mock implementation)
    fn hash_rp_id(&self, rp_id: &str) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let rp_id_bytes = rp_id.as_bytes();
        
        for (i, byte) in rp_id_bytes.iter().enumerate() {
            if i < 32 {
                hash[i] = *byte;
            }
        }
        
        hash
    }
    
    /// Hash client data (mock implementation)
    fn hash_client_data(&self, client_data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        
        for (i, byte) in client_data.iter().enumerate() {
            if i < 32 {
                hash[i] = *byte;
            }
        }
        
        hash
    }
    
    /// Get stored credentials for a user
    pub fn get_credentials_for_user(&self, user_id: &str) -> Vec<&MockCredential> {
        self.credentials.values()
            .filter(|cred| cred.user_id == user_id)
            .collect()
    }
    
    /// Create an invalid attestation response (for negative testing)
    pub fn create_invalid_attestation_response(&self, challenge: &str, error_type: &str) -> Value {
        let mut response = json!({
            "id": "invalid_credential_id",
            "rawId": "invalid_credential_id",
            "response": {
                "clientDataJSON": self.create_client_data_json("webauthn.create", challenge, "https://example.com"),
                "attestationObject": "invalid_attestation_object"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });
        
        match error_type {
            "invalid_client_data" => {
                response["response"]["clientDataJSON"] = json!("invalid_base64!");
            },
            "wrong_origin" => {
                response["response"]["clientDataJSON"] = json!(
                    self.create_client_data_json("webauthn.create", challenge, "https://evil.com")
                );
            },
            "wrong_type" => {
                response["response"]["clientDataJSON"] = json!(
                    self.create_client_data_json("webauthn.get", challenge, "https://example.com")
                );
            },
            "malformed_attestation" => {
                response["response"]["attestationObject"] = json!("malformed!");
            },
            _ => {}
        }
        
        response
    }
    
    /// Create an invalid assertion response (for negative testing)
    pub fn create_invalid_assertion_response(&self, challenge: &str, credential_id: &str, error_type: &str) -> Value {
        let mut response = json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "authenticatorData": self.create_authenticator_data("example.com", 1),
                "clientDataJSON": self.create_client_data_json("webauthn.get", challenge, "https://example.com"),
                "signature": "invalid_signature",
                "userHandle": base64url::encode(b"user123")
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });
        
        match error_type {
            "invalid_signature" => {
                response["response"]["signature"] = json!("invalid_signature!");
            },
            "wrong_origin" => {
                response["response"]["clientDataJSON"] = json!(
                    self.create_client_data_json("webauthn.get", challenge, "https://evil.com")
                );
            },
            "tampered_auth_data" => {
                response["response"]["authenticatorData"] = json!("tampered_data!");
            },
            "wrong_user_handle" => {
                response["response"]["userHandle"] = json!(base64url::encode(b"wrong_user"));
            },
            _ => {}
        }
        
        response
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}