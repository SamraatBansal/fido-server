//! Common test helper functions and utilities

use crate::common::{TestContext, TestResult, TestError};
use actix_web::{test, App, http::{StatusCode, Method}};
use actix_web::dev::ServiceResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};

/// HTTP test helper for making requests to the test server
pub struct HttpTestHelper {
    app: actix_web::App<>,
}

impl HttpTestHelper {
    pub fn new() -> Self {
        Self {
            app: test::init_service(
                App::new().configure(fido_server::routes::configure_routes)
            ).await,
        }
    }

    /// Make a POST request with JSON body
    pub async fn post_json<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> TestResult<ServiceResponse> {
        let req = test::TestRequest::post()
            .uri(path)
            .set_json(body)
            .to_request();

        Ok(test::call_service(&self.app, req).await)
    }

    /// Make a GET request
    pub async fn get(&self, path: &str) -> TestResult<ServiceResponse> {
        let req = test::TestRequest::get()
            .uri(path)
            .to_request();

        Ok(test::call_service(&self.app, req).await)
    }

    /// Make a request with custom method and headers
    pub async fn request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        headers: Option<HashMap<&str, &str>>,
    ) -> TestResult<ServiceResponse> {
        let mut req = test::TestRequest::new()
            .method(method)
            .uri(path);

        if let Some(body_data) = body {
            req = req.set_json(body_data);
        }

        if let Some(header_map) = headers {
            for (key, value) in header_map {
                req = req.insert_header((key.to_string(), value.to_string()));
            }
        }

        Ok(test::call_service(&self.app, req.to_request()).await)
    }

    /// Extract JSON response body
    pub async fn json_body<T: for<'de> Deserialize<'de>>(
        response: ServiceResponse,
    ) -> TestResult<T> {
        let body = test::read_body(response).await;
        serde_json::from_slice(&body).map_err(TestError::Serialization)
    }
}

/// Database test helper for setting up test data
pub struct DatabaseTestHelper {
    // In a real implementation, this would manage a test database connection
    test_data: HashMap<String, serde_json::Value>,
}

impl DatabaseTestHelper {
    pub fn new() -> Self {
        Self {
            test_data: HashMap::new(),
        }
    }

    /// Insert test user data
    pub fn insert_user(&mut self, context: &TestContext) -> TestResult<()> {
        let user_data = serde_json::json!({
            "id": context.user_id,
            "username": context.username,
            "display_name": context.display_name,
            "created_at": context.created_at,
            "is_active": true
        });

        self.test_data.insert(
            format!("user:{}", context.username),
            user_data,
        );
        Ok(())
    }

    /// Insert test credential data
    pub fn insert_credential(&mut self, context: &TestContext) -> TestResult<()> {
        let credential_data = serde_json::json!({
            "id": Uuid::new_v4(),
            "user_id": context.user_id,
            "credential_id": context.credential_id,
            "public_key": general_purpose::URL_SAFE.encode(vec![0u8; 32]),
            "sign_count": 0,
            "created_at": context.created_at,
            "is_active": true
        });

        self.test_data.insert(
            format!("credential:{}", context.credential_id),
            credential_data,
        );
        Ok(())
    }

    /// Insert test challenge data
    pub fn insert_challenge(&mut self, context: &TestContext, challenge_type: &str) -> TestResult<()> {
        let challenge_data = serde_json::json!({
            "id": Uuid::new_v4(),
            "challenge_hash": general_purpose::URL_SAFE.encode(context.challenge.as_bytes()),
            "user_id": context.user_id,
            "challenge_type": challenge_type,
            "expires_at": chrono::Utc::now() + chrono::Duration::minutes(5),
            "created_at": context.created_at,
            "used_at": null
        });

        self.test_data.insert(
            format!("challenge:{}", context.challenge),
            challenge_data,
        );
        Ok(())
    }

    /// Check if user exists
    pub fn user_exists(&self, username: &str) -> bool {
        self.test_data.contains_key(&format!("user:{}", username))
    }

    /// Check if credential exists
    pub fn credential_exists(&self, credential_id: &str) -> bool {
        self.test_data.contains_key(&format!("credential:{}", credential_id))
    }

    /// Check if challenge exists
    pub fn challenge_exists(&self, challenge: &str) -> bool {
        self.test_data.contains_key(&format!("challenge:{}", challenge))
    }

    /// Clear all test data
    pub fn clear(&mut self) {
        self.test_data.clear();
    }
}

/// Assertion helpers for test validation
pub struct AssertionHelper;

impl AssertionHelper {
    /// Assert HTTP status code
    pub fn assert_status(response: &ServiceResponse, expected: StatusCode) -> TestResult<()> {
        assert_eq!(
            response.status(),
            expected,
            "Expected status {}, got {}",
            expected,
            response.status()
        );
        Ok(())
    }

    /// Assert response contains required JSON fields
    pub fn assert_json_fields<T: Serialize>(
        response: &ServiceResponse,
        required_fields: &[&str],
    ) -> TestResult<()> {
        let body = test::read_body(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body)?;

        for field in required_fields {
            assert!(
                json.get(field).is_some(),
                "Missing required field: {}",
                field
            );
        }

        Ok(())
    }

    /// Assert JSON field value
    pub fn assert_json_field_value<T: PartialEq + serde::de::DeserializeOwned>(
        response: &ServiceResponse,
        field: &str,
        expected_value: T,
    ) -> TestResult<()> {
        let body = test::read_body(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body)?;

        let actual_value: T = serde_json::from_value(
            json.get(field)
                .ok_or_else(|| TestError::Setup(format!("Field {} not found", field)))?
                .clone(),
        )?;

        assert_eq!(
            actual_value, expected_value,
            "Field {} value mismatch",
            field
        );

        Ok(())
    }

    /// Assert base64url string is valid
    pub fn assert_valid_base64url(s: &str) -> TestResult<()> {
        general_purpose::URL_SAFE
            .decode(s)
            .map_err(TestError::Base64)?;
        Ok(())
    }

    /// Assert challenge format and uniqueness
    pub fn assert_valid_challenge(challenge: &str) -> TestResult<()> {
        // Check base64url encoding
        Self::assert_valid_base64url(challenge)?;

        // Check minimum length (at least 16 bytes when decoded)
        let decoded = general_purpose::URL_SAFE.decode(challenge)?;
        assert!(
            decoded.len() >= 16,
            "Challenge too short: {} bytes",
            decoded.len()
        );

        Ok(())
    }

    /// Assert credential ID format
    pub fn assert_valid_credential_id(credential_id: &str) -> TestResult<()> {
        // Check base64url encoding
        Self::assert_valid_base64url(credential_id)?;

        // Check reasonable length
        let decoded = general_purpose::URL_SAFE.decode(credential_id)?;
        assert!(
            decoded.len() >= 16 && decoded.len() <= 1024,
            "Credential ID length invalid: {} bytes",
            decoded.len()
        );

        Ok(())
    }

    /// Assert client data JSON structure
    pub fn assert_valid_client_data_json(client_data_json: &str, expected_type: &str) -> TestResult<()> {
        // Decode base64url
        let decoded = general_purpose::URL_SAFE.decode(client_data_json)?;
        let json_str = String::from_utf8(decoded)
            .map_err(|_| TestError::Setup("Invalid UTF-8 in client data".to_string()))?;

        // Parse JSON
        let client_data: serde_json::Value = serde_json::from_str(&json_str)?;

        // Check required fields
        let required_fields = ["type", "challenge", "origin"];
        for field in &required_fields {
            assert!(
                client_data.get(field).is_some(),
                "Missing client data field: {}",
                field
            );
        }

        // Check type matches expected
        if let Some(actual_type) = client_data.get("type").and_then(|v| v.as_str()) {
            assert_eq!(
                actual_type, expected_type,
                "Client data type mismatch: expected {}, got {}",
                expected_type, actual_type
            );
        } else {
            return Err(TestError::Setup("Invalid type field in client data".to_string()));
        }

        Ok(())
    }
}

/// Timing helper for performance and timeout tests
pub struct TimingHelper;

impl TimingHelper {
    /// Measure execution time of an async function
    pub async fn measure_time<F, Fut, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let start = std::time::Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Assert execution time is within bounds
    pub fn assert_duration_within(
        duration: Duration,
        min_ms: u64,
        max_ms: u64,
    ) -> TestResult<()> {
        let duration_ms = duration.as_millis() as u64;
        
        assert!(
            duration_ms >= min_ms,
            "Duration too short: {}ms (expected >= {}ms)",
            duration_ms, min_ms
        );
        
        assert!(
            duration_ms <= max_ms,
            "Duration too long: {}ms (expected <= {}ms)",
            duration_ms, max_ms
        );

        Ok(())
    }

    /// Wait for a specified duration
    pub async fn wait(duration: Duration) {
        sleep(duration).await;
    }
}

/// Security test helper
pub struct SecurityTestHelper;

impl SecurityTestHelper {
    /// Generate malformed JSON strings for testing
    pub fn malformed_json_samples() -> Vec<&'static str> {
        vec![
            "", // Empty
            "{", // Incomplete object
            "}", // Unmatched brace
            "[", // Incomplete array
            "]", // Unmatched bracket
            "{\"key\":}", // Missing value
            "{\"key\": \"value\"", // Missing closing brace
            "{\"key\": \"value\",}", // Trailing comma
            "null", // Just null
            "undefined", // JavaScript undefined
            "{\"key\": undefined}", // Undefined value
            "{\"key\": NaN}", // NaN value
            "{\"key\": Infinity}", // Infinity value
        ]
    }

    /// Generate oversized payloads for DoS testing
    pub fn oversized_payloads() -> Vec<String> {
        vec![
            "a".repeat(1024 * 1024), // 1MB string
            " ".repeat(1024 * 1024), // 1MB whitespace
            serde_json::json!({
                "data": "x".repeat(1024 * 1024)
            }).to_string(), // 1MB JSON field
        ]
    }

    /// Generate invalid base64url strings
    pub fn invalid_base64url_samples() -> Vec<&'static str> {
        vec![
            "", // Empty
            "!", // Invalid character
            "invalid!", // Contains invalid character
            "====", // Too many padding characters
            "a=b", // Invalid padding position
            "a", // Too short
        ]
    }

    /// Generate SQL injection payloads
    pub fn sql_injection_payloads() -> Vec<&'static str> {
        vec![
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' UNION SELECT * FROM users --",
            "'; UPDATE users SET password='hacked'; --",
        ]
    }

    /// Generate XSS payloads
    pub fn xss_payloads() -> Vec<&'static str> {
        vec![
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",
            "<svg onload=alert('xss')>",
        ]
    }
}

/// Concurrency test helper
pub struct ConcurrencyTestHelper;

impl ConcurrencyTestHelper {
    /// Run multiple tasks concurrently and collect results
    pub async fn run_concurrent<F, Fut, T>(
        tasks: Vec<F>,
        max_concurrent: usize,
    ) -> Vec<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use futures::stream::{self, StreamExt};
        
        stream::iter(tasks)
            .map(|task| tokio::spawn(task()))
            .buffer_unordered(max_concurrent)
            .map(|result| result.unwrap_or_else(|e| panic!("Task failed: {:?}", e)))
            .collect()
            .await
    }

    /// Generate concurrent registration requests
    pub fn generate_registration_requests(count: usize) -> Vec<crate::common::fixtures::RegistrationStartRequestFixture> {
        (0..count)
            .map(|i| {
                crate::common::fixtures::RegistrationStartRequestFixture::with_username(
                    &format!("user{}@example.com", i)
                )
            })
            .collect()
    }

    /// Generate concurrent authentication requests
    pub fn generate_authentication_requests(count: usize) -> Vec<crate::common::fixtures::AuthenticationStartRequestFixture> {
        (0..count)
            .map(|i| {
                crate::common::fixtures::AuthenticationStartRequestFixture::with_username(
                    &format!("user{}@example.com", i)
                )
            })
            .collect()
    }
}