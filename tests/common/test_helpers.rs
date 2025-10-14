//! Test helper functions and utilities
//!
//! This module provides common helper functions for setting up tests,
//! making HTTP requests, and validating responses.

use actix_web::test::{TestRequest, call_service};
use actix_web::{web, App, http::StatusCode};
use serde_json::Value;
use std::collections::HashMap;

/// HTTP client for making test requests
pub struct TestClient {
    app: actix_web::test::TestServer,
}

impl TestClient {
    /// Create a new test client
    pub fn new() -> Self {
        Self {
            app: super::create_test_app(),
        }
    }
    
    /// Make a POST request to the given path with JSON body
    pub async fn post_json(&self, path: &str, body: Value) -> TestResponse {
        let req = TestRequest::post()
            .uri(path)
            .set_json(&body)
            .to_request();
            
        let resp = call_service(&self.app, req).await;
        
        TestResponse {
            status: resp.status(),
            body: actix_web::test::read_body_json(resp).await,
        }
    }
    
    /// Make a POST request with malformed JSON
    pub async fn post_malformed_json(&self, path: &str, body: &str) -> TestResponse {
        let req = TestRequest::post()
            .uri(path)
            .set_header("content-type", "application/json")
            .set_payload(body)
            .to_request();
            
        let resp = call_service(&self.app, req).await;
        
        TestResponse {
            status: resp.status(),
            body: serde_json::json!({}), // Empty for malformed requests
        }
    }
    
    /// Make a POST request with custom headers
    pub async fn post_with_headers(&self, path: &str, body: Value, headers: HashMap<&str, &str>) -> TestResponse {
        let mut req = TestRequest::post()
            .uri(path)
            .set_json(&body);
            
        for (key, value) in headers {
            req = req.set_header(key, value);
        }
        
        let resp = call_service(&self.app, req.to_request()).await;
        
        TestResponse {
            status: resp.status(),
            body: actix_web::test::read_body_json(resp).await,
        }
    }
}

/// Test response wrapper
pub struct TestResponse {
    pub status: StatusCode,
    pub body: Value,
}

impl TestResponse {
    /// Assert that the response has the expected status code
    pub fn assert_status(&self, expected: StatusCode) {
        assert_eq!(self.status, expected, "Unexpected status code. Response body: {}", self.body);
    }
    
    /// Assert that the response is a success (2xx)
    pub fn assert_success(&self) {
        assert!(self.status.is_success(), "Expected success status, got {}. Response body: {}", self.status, self.body);
    }
    
    /// Assert that the response is a client error (4xx)
    pub fn assert_client_error(&self) {
        assert!(self.status.is_client_error(), "Expected client error status, got {}. Response body: {}", self.status, self.body);
    }
    
    /// Assert that the response is a server error (5xx)
    pub fn assert_server_error(&self) {
        assert!(self.status.is_server_error(), "Expected server error status, got {}. Response body: {}", self.status, self.body);
    }
    
    /// Get the response body as JSON
    pub fn json(&self) -> &Value {
        &self.body
    }
    
    /// Assert that the response contains a specific field
    pub fn assert_has_field(&self, field: &str) {
        assert!(self.body.get(field).is_some(), "Response missing field '{}'. Body: {}", field, self.body);
    }
    
    /// Assert that a field has a specific value
    pub fn assert_field_equals(&self, field: &str, expected: &Value) {
        let actual = self.body.get(field).unwrap_or(&Value::Null);
        assert_eq!(actual, expected, "Field '{}' has unexpected value. Expected: {}, Actual: {}", field, expected, actual);
    }
    
    /// Assert that the response indicates success
    pub fn assert_fido_success(&self) {
        self.assert_field_equals("status", &Value::String("ok".to_string()));
        self.assert_field_equals("errorMessage", &Value::String("".to_string()));
    }
    
    /// Assert that the response indicates failure with specific error
    pub fn assert_fido_error(&self, expected_error: &str) {
        self.assert_field_equals("status", &Value::String("failed".to_string()));
        let error_message = self.body["errorMessage"].as_str().unwrap_or("");
        assert!(error_message.contains(expected_error), 
                "Error message '{}' does not contain expected text '{}'", error_message, expected_error);
    }
}

/// Database test helpers
pub mod db_helpers {
    use uuid::Uuid;
    
    /// Create a test user in the database
    pub async fn create_test_user(username: &str, display_name: &str) -> Uuid {
        // This would interact with the actual database in a real implementation
        // For now, return a mock UUID
        Uuid::new_v4()
    }
    
    /// Create a test credential for a user
    pub async fn create_test_credential(user_id: Uuid, credential_id: &str) -> Uuid {
        // This would create a credential in the database
        Uuid::new_v4()
    }
    
    /// Clean up test data
    pub async fn cleanup_test_data() {
        // This would clean up test data from the database
    }
    
    /// Verify that a user exists in the database
    pub async fn user_exists(username: &str) -> bool {
        // This would check if a user exists in the database
        true // Mock implementation
    }
    
    /// Verify that a credential exists for a user
    pub async fn credential_exists(user_id: Uuid, credential_id: &str) -> bool {
        // This would check if a credential exists
        true // Mock implementation
    }
}

/// Timing helpers for performance tests
pub mod timing {
    use std::time::{Duration, Instant};
    
    /// Measure the execution time of an async function
    pub async fn measure_async<F, Fut, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let start = Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }
    
    /// Assert that an operation completes within a time limit
    pub fn assert_within_time_limit<T>(result: (T, Duration), limit: Duration) -> T {
        let (value, duration) = result;
        assert!(duration <= limit, "Operation took {:?}, which exceeds limit of {:?}", duration, limit);
        value
    }
}

/// Concurrency helpers for load testing
pub mod concurrency {
    use futures::future::join_all;
    use std::future::Future;
    
    /// Run multiple async operations concurrently
    pub async fn run_concurrent<F, Fut, T>(operations: Vec<F>) -> Vec<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let futures: Vec<_> = operations.into_iter().map(|op| op()).collect();
        join_all(futures).await
    }
    
    /// Run the same operation multiple times concurrently
    pub async fn run_concurrent_same<F, Fut, T>(operation: F, count: usize) -> Vec<T>
    where
        F: Fn() -> Fut + Clone,
        Fut: Future<Output = T>,
    {
        let operations: Vec<_> = (0..count).map(|_| operation.clone()).collect();
        run_concurrent(operations).await
    }
}

/// Validation helpers
pub mod validation {
    use serde_json::Value;
    use super::super::base64url;
    
    /// Validate that a string is valid base64url
    pub fn is_valid_base64url(s: &str) -> bool {
        base64url::decode(s).is_ok()
    }
    
    /// Validate challenge format and length
    pub fn validate_challenge(challenge: &str) -> Result<(), String> {
        if challenge.is_empty() {
            return Err("Challenge cannot be empty".to_string());
        }
        
        if !is_valid_base64url(challenge) {
            return Err("Challenge must be valid base64url".to_string());
        }
        
        let decoded = base64url::decode(challenge).map_err(|e| format!("Invalid base64url: {}", e))?;
        
        if decoded.len() < 16 {
            return Err("Challenge must be at least 16 bytes".to_string());
        }
        
        if decoded.len() > 64 {
            return Err("Challenge must be at most 64 bytes".to_string());
        }
        
        Ok(())
    }
    
    /// Validate user ID format
    pub fn validate_user_id(user_id: &str) -> Result<(), String> {
        if user_id.is_empty() {
            return Err("User ID cannot be empty".to_string());
        }
        
        if !is_valid_base64url(user_id) {
            return Err("User ID must be valid base64url".to_string());
        }
        
        Ok(())
    }
    
    /// Validate credential ID format
    pub fn validate_credential_id(credential_id: &str) -> Result<(), String> {
        if credential_id.is_empty() {
            return Err("Credential ID cannot be empty".to_string());
        }
        
        if !is_valid_base64url(credential_id) {
            return Err("Credential ID must be valid base64url".to_string());
        }
        
        Ok(())
    }
    
    /// Validate attestation options response schema
    pub fn validate_attestation_options_response(response: &Value) -> Result<(), String> {
        // Check required fields
        let required_fields = ["status", "rp", "user", "challenge", "pubKeyCredParams"];
        for field in &required_fields {
            if response.get(field).is_none() {
                return Err(format!("Missing required field: {}", field));
            }
        }
        
        // Validate challenge
        let challenge = response["challenge"].as_str().ok_or("Challenge must be a string")?;
        validate_challenge(challenge)?;
        
        // Validate user ID
        let user_id = response["user"]["id"].as_str().ok_or("User ID must be a string")?;
        validate_user_id(user_id)?;
        
        // Validate pubKeyCredParams is an array
        if !response["pubKeyCredParams"].is_array() {
            return Err("pubKeyCredParams must be an array".to_string());
        }
        
        Ok(())
    }
    
    /// Validate assertion options response schema
    pub fn validate_assertion_options_response(response: &Value) -> Result<(), String> {
        // Check required fields
        let required_fields = ["status", "challenge", "rpId"];
        for field in &required_fields {
            if response.get(field).is_none() {
                return Err(format!("Missing required field: {}", field));
            }
        }
        
        // Validate challenge
        let challenge = response["challenge"].as_str().ok_or("Challenge must be a string")?;
        validate_challenge(challenge)?;
        
        // Validate allowCredentials if present
        if let Some(allow_creds) = response.get("allowCredentials") {
            if !allow_creds.is_array() {
                return Err("allowCredentials must be an array".to_string());
            }
            
            for cred in allow_creds.as_array().unwrap() {
                let cred_id = cred["id"].as_str().ok_or("Credential ID must be a string")?;
                validate_credential_id(cred_id)?;
            }
        }
        
        Ok(())
    }
}