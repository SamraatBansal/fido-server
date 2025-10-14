// Common test utilities and data factories for FIDO2 server testing

pub mod test_data;
pub mod test_server;
pub mod assertions;

use serde_json::Value;
use std::collections::HashMap;

/// Common test configuration
pub struct TestConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub timeout: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            rp_id: "example.com".to_string(),
            rp_name: "Example Corporation".to_string(),
            origin: "https://example.com".to_string(),
            timeout: 60000,
        }
    }
}

/// Test result wrapper for consistent error handling
#[derive(Debug)]
pub struct TestResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> TestResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
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

    pub fn encode_string(data: &str) -> String {
        encode(data.as_bytes())
    }
}

/// HTTP client utilities for testing
pub mod http_client {
    use actix_web::test;
    use serde_json::Value;
    use std::collections::HashMap;

    pub async fn post_json(
        app: &mut test::TestServer,
        path: &str,
        body: Value,
    ) -> Result<(u16, Value), Box<dyn std::error::Error>> {
        let req = test::TestRequest::post()
            .uri(path)
            .insert_header(("content-type", "application/json"))
            .set_json(&body)
            .to_request();

        let resp = test::call_service(app, req).await;
        let status = resp.status().as_u16();
        let body: Value = test::read_body_json(resp).await;

        Ok((status, body))
    }

    pub async fn get_json(
        app: &mut test::TestServer,
        path: &str,
    ) -> Result<(u16, Value), Box<dyn std::error::Error>> {
        let req = test::TestRequest::get()
            .uri(path)
            .insert_header(("content-type", "application/json"))
            .to_request();

        let resp = test::call_service(app, req).await;
        let status = resp.status().as_u16();
        let body: Value = test::read_body_json(resp).await;

        Ok((status, body))
    }
}

/// Timing utilities for challenge expiration tests
pub mod timing {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn timestamp_after(seconds: u64) -> u64 {
        current_timestamp() + seconds
    }

    pub fn is_expired(timestamp: u64, max_age_seconds: u64) -> bool {
        current_timestamp() > timestamp + max_age_seconds
    }
}

/// Security test utilities
pub mod security {
    use rand::Rng;
    use sha2::{Digest, Sha256};

    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }

    pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn tamper_base64url(original: &str, position: usize) -> String {
        let mut chars: Vec<char> = original.chars().collect();
        if position < chars.len() {
            chars[position] = if chars[position] == 'A' { 'B' } else { 'A' };
        }
        chars.into_iter().collect()
    }
}