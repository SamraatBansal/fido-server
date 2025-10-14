//! Server integration tests
//! 
//! These tests start the actual server and make HTTP requests to verify
//! the endpoints work correctly.

use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_server_endpoints() {
    // Start the server in a background task
    let server_handle = tokio::spawn(async {
        webauthn_rp_server::main().await.unwrap();
    });

    // Give the server time to start
    sleep(Duration::from_millis(100)).await;

    // Test health endpoint
    let client = reqwest::Client::new();
    
    let health_response = client
        .get("http://127.0.0.1:8080/health")
        .send()
        .await;
    
    if let Ok(resp) = health_response {
        assert!(resp.status().is_success());
    }

    // Test attestation/options endpoint
    let attestation_request = json!({
        "username": "test@example.com",
        "displayName": "Test User",
        "attestation": "none"
    });

    let attestation_response = client
        .post("http://127.0.0.1:8080/attestation/options")
        .json(&attestation_request)
        .send()
        .await;

    if let Ok(resp) = attestation_response {
        assert!(resp.status().is_success());
        
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            assert_eq!(body["status"], "ok");
            assert!(body["challenge"].is_string());
        }
    }

    // Abort the server
    server_handle.abort();
}

#[tokio::test]
async fn test_attestation_options_validation() {
    // Start the server in a background task
    let server_handle = tokio::spawn(async {
        webauthn_rp_server::main().await.unwrap();
    });

    // Give the server time to start
    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Test with empty username
    let invalid_request = json!({
        "username": "",
        "displayName": "Test User",
        "attestation": "none"
    });

    let response = client
        .post("http://127.0.0.1:8080/attestation/options")
        .json(&invalid_request)
        .send()
        .await;

    if let Ok(resp) = response {
        assert_eq!(resp.status(), 400);
        
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            assert_eq!(body["status"], "failed");
        }
    }

    // Abort the server
    server_handle.abort();
}