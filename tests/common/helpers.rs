//! Test helper functions and utilities

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

use crate::common::{ServerResponse, TestConfig};

/// HTTP client for testing
pub struct TestClient {
    client: Client,
    config: TestConfig,
}

impl TestClient {
    /// Create a new test client
    pub fn new(config: TestConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Make a POST request with JSON body
    pub async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<R, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/{}", self.config.base_url, endpoint);
        
        let response = timeout(
            self.config.timeout,
            self.client
                .post(&url)
                .json(body)
                .send()
        )
        .await??;

        if response.status().is_success() {
            let result = response.json::<R>().await?;
            Ok(result)
        } else {
            let error_text = response.text().await?;
            Err(format!("HTTP {}: {}", response.status(), error_text).into())
        }
    }

    /// Make a GET request
    pub async fn get<R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
    ) -> Result<R, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/{}", self.config.base_url, endpoint);
        
        let response = timeout(
            self.config.timeout,
            self.client.get(&url).send()
        )
        .await??;

        if response.status().is_success() {
            let result = response.json::<R>().await?;
            Ok(result)
        } else {
            let error_text = response.text().await?;
            Err(format!("HTTP {}: {}", response.status(), error_text).into())
        }
    }

    /// Check if server is healthy
    pub async fn health_check(&self) -> bool {
        match self.get::<serde_json::Value>("/health").await {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Assert that a server response indicates success
pub fn assert_success_response(response: &ServerResponse) {
    assert_eq!(response.status, "ok", "Expected success status, got: {}", response.status);
    assert!(
        response.errorMessage.is_empty(),
        "Expected empty error message, got: {}",
        response.errorMessage
    );
}

/// Assert that a server response indicates failure
pub fn assert_failure_response(response: &ServerResponse, expected_error: Option<&str>) {
    assert_eq!(response.status, "failed", "Expected failed status, got: {}", response.status);
    
    if let Some(expected_msg) = expected_error {
        assert!(
            response.errorMessage.contains(expected_msg),
            "Expected error message to contain '{}', got: '{}'",
            expected_msg,
            response.errorMessage
        );
    } else {
        assert!(
            !response.errorMessage.is_empty(),
            "Expected non-empty error message for failed response"
        );
    }
}

/// Validate that a challenge is properly formatted
pub fn validate_challenge(challenge: &str) -> Result<(), String> {
    if challenge.is_empty() {
        return Err("Challenge cannot be empty".to_string());
    }

    // Check if it's valid base64url
    if challenge.contains('+') || challenge.contains('/') || challenge.contains('=') {
        return Err("Challenge contains invalid base64url characters".to_string());
    }

    // Try to decode it
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge)
        .map_err(|e| format!("Invalid base64url encoding: {}", e))?;

    // Check length (should be between 16 and 64 bytes when decoded)
    let decoded_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge)
        .unwrap()
        .len();
    
    if decoded_len < 16 || decoded_len > 64 {
        return Err(format!(
            "Challenge length must be between 16 and 64 bytes when decoded, got {}",
            decoded_len
        ));
    }

    Ok(())
}

/// Validate RP entity structure
pub fn validate_rp_entity(rp: &serde_json::Value) -> Result<(), String> {
    let name = rp.get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid RP name")?;
    
    let id = rp.get("id")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid RP id")?;

    if name.is_empty() {
        return Err("RP name cannot be empty".to_string());
    }

    if id.is_empty() {
        return Err("RP id cannot be empty".to_string());
    }

    // Basic domain validation for RP ID
    if !id.contains('.') {
        return Err("RP ID should be a valid domain".to_string());
    }

    Ok(())
}

/// Validate user entity structure
pub fn validate_user_entity(user: &serde_json::Value) -> Result<(), String> {
    let id = user.get("id")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid user id")?;
    
    let name = user.get("name")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid user name")?;
    
    let display_name = user.get("displayName")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid user displayName")?;

    if id.is_empty() {
        return Err("User id cannot be empty".to_string());
    }

    if name.is_empty() {
        return Err("User name cannot be empty".to_string());
    }

    if display_name.is_empty() {
        return Err("User displayName cannot be empty".to_string());
    }

    // Validate that user id is valid base64url
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| "User id must be valid base64url".to_string())?;

    Ok(())
}

/// Validate public key credential parameters
pub fn validate_pub_key_cred_params(params: &serde_json::Value) -> Result<(), String> {
    let params_array = params
        .as_array()
        .ok_or("pubKeyCredParams must be an array")?;

    if params_array.is_empty() {
        return Err("pubKeyCredParams cannot be empty".to_string());
    }

    for param in params_array {
        let cred_type = param.get("type")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid credential type")?;
        
        let alg = param.get("alg")
            .and_then(|v| v.as_i64())
            .ok_or("Missing or invalid algorithm")?;

        if cred_type != "public-key" {
            return Err("Credential type must be 'public-key'".to_string());
        }

        // Validate algorithm is a supported COSE algorithm
        match alg {
            -7 | -8 | -35 | -36 | -257 | -258 | -259 | -65535 => {
                // Supported algorithms
            }
            _ => {
                return Err(format!("Unsupported algorithm: {}", alg));
            }
        }
    }

    Ok(())
}

/// Retry mechanism for flaky tests
pub async fn retry_async<F, T, E>(
    operation: F,
    max_attempts: u32,
    delay: Duration,
) -> Result<T, E>
where
    F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
    E: std::fmt::Display,
{
    let mut last_error = None;
    
    for attempt in 1..=max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    
    Err(last_error.unwrap())
}

/// Measure execution time of an operation
pub async fn measure_time<F, T>(operation: F) -> (T, Duration)
where
    F: std::future::Future<Output = T>,
{
    let start = std::time::Instant::now();
    let result = operation.await;
    let duration = start.elapsed();
    (result, duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_challenge() {
        // Valid challenge
        let valid_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0u8; 32]);
        assert!(validate_challenge(&valid_challenge).is_ok());

        // Empty challenge
        assert!(validate_challenge("").is_err());

        // Invalid base64url
        assert!(validate_challenge("invalid+base64/=").is_err());

        // Too short
        let short_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0u8; 8]);
        assert!(validate_challenge(&short_challenge).is_err());

        // Too long
        let long_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0u8; 100]);
        assert!(validate_challenge(&long_challenge).is_err());
    }

    #[test]
    fn test_assert_success_response() {
        let response = ServerResponse {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
        };
        assert_success_response(&response);
    }

    #[test]
    #[should_panic(expected = "Expected success status")]
    fn test_assert_success_response_panics() {
        let response = ServerResponse {
            status: "failed".to_string(),
            errorMessage: "Some error".to_string(),
        };
        assert_success_response(&response);
    }
}