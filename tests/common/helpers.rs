//! Test helper functions and utilities

use actix_web::{dev::ServiceResponse, test, App};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

/// Mock handler for attestation options
async fn mock_attestation_options(
    req: actix_web::web::Json<Value>,
) -> Result<actix_web::web::Json<Value>, actix_web::Error> {
    let request = req.into_inner();
    
    // Basic validation
    if request.get("username").is_none() || request.get("displayName").is_none() {
        return Err(actix_web::error::ErrorBadRequest("Missing required fields"));
    }
    
    let response = json!({
        "status": "ok",
        "errorMessage": "",
        "challenge": generate_secure_challenge(),
        "rp": { "name": "Example RP", "id": "example.com" },
        "user": { 
            "id": URL_SAFE_NO_PAD.encode(request["username"].as_str().unwrap_or("")),
            "name": request["username"],
            "displayName": request["displayName"]
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "timeout": 60000,
        "attestation": "direct"
    });
    
    Ok(actix_web::web::Json(response))
}

/// Mock handler for attestation result
async fn mock_attestation_result(
    req: actix_web::web::Json<Value>,
) -> Result<actix_web::web::Json<Value>, actix_web::Error> {
    let request = req.into_inner();
    
    // Basic validation
    if request.get("id").is_none() || request.get("response").is_none() {
        return Err(actix_web::error::ErrorBadRequest("Missing required fields"));
    }
    
    let response = json!({
        "status": "ok",
        "errorMessage": ""
    });
    
    Ok(actix_web::web::Json(response))
}

/// Mock handler for assertion options
async fn mock_assertion_options(
    req: actix_web::web::Json<Value>,
) -> Result<actix_web::web::Json<Value>, actix_web::Error> {
    let request = req.into_inner();
    
    // Basic validation
    if request.get("username").is_none() {
        return Err(actix_web::error::ErrorBadRequest("Missing username"));
    }
    
    let response = json!({
        "status": "ok",
        "errorMessage": "",
        "challenge": generate_secure_challenge(),
        "rpId": "example.com",
        "allowCredentials": [{ 
            "type": "public-key", 
            "id": URL_SAFE_NO_PAD.encode("credential_id_32_bytes_long_!!")
        }],
        "timeout": 60000,
        "userVerification": "preferred"
    });
    
    Ok(actix_web::web::Json(response))
}

/// Mock handler for assertion result
async fn mock_assertion_result(
    req: actix_web::web::Json<Value>,
) -> Result<actix_web::web::Json<Value>, actix_web::Error> {
    let request = req.into_inner();
    
    // Basic validation
    if request.get("id").is_none() || request.get("response").is_none() {
        return Err(actix_web::error::ErrorBadRequest("Missing required fields"));
    }
    
    let response = json!({
        "status": "ok",
        "errorMessage": ""
    });
    
    Ok(actix_web::web::Json(response))
}

/// Generate a secure random challenge
pub fn generate_secure_challenge() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a random username
pub fn random_username() -> String {
    format!("user_{}", Uuid::new_v4().to_string().replace("-", "")[..8].to_string())
}

/// Generate a random credential ID
pub fn random_credential_id() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validate base64url string
pub fn is_valid_base64url(s: &str) -> bool {
    URL_SAFE_NO_PAD.decode(s).is_ok()
}

/// Extract challenge from client data JSON
pub fn extract_challenge_from_client_data(client_data_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client_data_bytes = URL_SAFE_NO_PAD.decode(client_data_b64)?;
    let client_data: Value = serde_json::from_slice(&client_data_bytes)?;
    
    client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Challenge not found in client data".into())
}

/// Extract origin from client data JSON
pub fn extract_origin_from_client_data(client_data_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client_data_bytes = URL_SAFE_NO_PAD.decode(client_data_b64)?;
    let client_data: Value = serde_json::from_slice(&client_data_bytes)?;
    
    client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Origin not found in client data".into())
}

/// Create a mock attestation object
pub fn create_mock_attestation_object(_challenge: &str) -> String {
    let mock_data = json!({
        "fmt": "packed",
        "attStmt": {},
        "authData": URL_SAFE_NO_PAD.encode("mock_authenticator_data")
    });
    
    URL_SAFE_NO_PAD.encode(mock_data.to_string())
}

/// Create a mock client data JSON
pub fn create_mock_client_data_json(challenge: &str, origin: &str, operation_type: &str) -> String {
    let client_data = json!({
        "type": operation_type,
        "challenge": challenge,
        "origin": origin
    });
    
    URL_SAFE_NO_PAD.encode(client_data.to_string())
}

/// Wait for async operation with timeout
pub async fn wait_with_timeout<F>(future: F, timeout: Duration) -> Result<F::Output, &'static str>
where
    F: std::future::Future,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err("Operation timed out"),
    }
}

/// Measure execution time of a function
pub async fn measure_time<F, R>(future: F) -> (R, Duration)
where
    F: std::future::Future<Output = R>,
{
    let start = std::time::Instant::now();
    let result = future.await;
    let duration = start.elapsed();
    (result, duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_secure_challenge() {
        let challenge1 = generate_secure_challenge();
        let challenge2 = generate_secure_challenge();
        
        assert_ne!(challenge1, challenge2);
        assert!(challenge1.len() >= 32);
        assert!(is_valid_base64url(&challenge1));
    }

    #[tokio::test]
    async fn test_random_username() {
        let username1 = random_username();
        let username2 = random_username();
        
        assert_ne!(username1, username2);
        assert!(username1.starts_with("user_"));
        assert!(username1.len() > 8);
    }

    #[tokio::test]
    async fn test_extract_challenge_from_client_data() {
        let challenge = "test_challenge_123";
        let client_data = create_mock_client_data_json(challenge, "https://example.com", "webauthn.create");
        
        let extracted = extract_challenge_from_client_data(&client_data).unwrap();
        assert_eq!(extracted, challenge);
    }

    #[tokio::test]
    async fn test_extract_origin_from_client_data() {
        let origin = "https://example.com";
        let client_data = create_mock_client_data_json("challenge", origin, "webauthn.create");
        
        let extracted = extract_origin_from_client_data(&client_data).unwrap();
        assert_eq!(extracted, origin);
    }
}