//! Common test utilities and data factories for FIDO2/WebAuthn testing
//!
//! This module provides shared test utilities, data factories, and helper functions
//! for comprehensive FIDO2/WebAuthn server testing.

pub mod data_factories;
pub mod test_helpers;
pub mod mock_authenticator;
pub mod security_vectors;

use actix_web::{test, web, App};
use fido_server::{routes, config::AppConfig};
use std::sync::Arc;

/// Test application factory for integration tests
pub fn create_test_app() -> actix_web::test::TestServer {
    test::start(|| {
        App::new()
            .configure(routes::configure_routes)
            .app_data(web::Data::new(Arc::new(create_test_config())))
    })
}

/// Create test configuration
pub fn create_test_config() -> AppConfig {
    AppConfig {
        server_host: "localhost".to_string(),
        server_port: 8080,
        database_url: "postgres://test:test@localhost/fido_test".to_string(),
        rp_id: "example.com".to_string(),
        rp_name: "Example Corporation".to_string(),
        rp_origin: "https://example.com".to_string(),
        challenge_timeout: 300,
        max_credentials_per_user: 10,
        require_user_verification: false,
        allowed_algorithms: vec![-7, -35, -36, -257, -258, -259],
    }
}

/// Base64URL encoding/decoding utilities for tests
pub mod base64url {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    
    pub fn encode(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }
    
    pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(data)
    }
}

/// Test result assertions
pub mod assertions {
    use serde_json::Value;
    
    pub fn assert_success_response(response: &Value) {
        assert_eq!(response["status"], "ok");
        assert_eq!(response["errorMessage"], "");
    }
    
    pub fn assert_error_response(response: &Value, expected_error: &str) {
        assert_eq!(response["status"], "failed");
        assert!(response["errorMessage"].as_str().unwrap().contains(expected_error));
    }
    
    pub fn assert_valid_challenge(challenge: &str) {
        assert!(!challenge.is_empty());
        assert!(challenge.len() >= 22); // Minimum 16 bytes base64url encoded
        assert!(challenge.len() <= 86); // Maximum 64 bytes base64url encoded
        // Verify it's valid base64url
        assert!(super::base64url::decode(challenge).is_ok());
    }
}