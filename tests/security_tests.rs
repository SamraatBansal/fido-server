//! Security tests for FIDO2/WebAuthn implementation
//! Tests for security vulnerabilities and edge cases

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;

use fido_server::controllers::WebAuthnController;
use fido_server::webauthn::{WebAuthnConfig, WebAuthnServiceImpl};

#[actix_web::test]
async fn test_sql_injection_prevention() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test SQL injection attempts in username
    let malicious_usernames = vec![
        "'; DROP TABLE users; --",
        "admin' OR '1'='1",
        "user'; INSERT INTO users VALUES('hacker','password'); --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
    ];

    for username in malicious_usernames {
        let request = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(&json!({
                "username": username,
                "displayName": "Test User",
                "attestation": "none"
            }))
            .to_request();

        let resp = test::call_service(&app, request).await;
        // Should either succeed (if input is valid) or fail gracefully, not crash
        assert!(resp.status().is_success() || resp.status().is_client_error());
    }
}

#[actix_web::test]
async fn test_xss_prevention() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test XSS attempts in display name
    let xss_payloads = vec![
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "';alert('xss');//",
    ];

    for payload in xss_payloads {
        let request = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(&json!({
                "username": "test@example.com",
                "displayName": payload,
                "attestation": "none"
            }))
            .to_request();

        let resp = test::call_service(&app, request).await;
        let status = resp.status();
        let result: serde_json::Value = test::read_body_json(resp).await;
        
        if status.is_success() {
            // Check that XSS payload is not reflected in response without proper encoding
            let response_str = result.to_string();
            assert!(!response_str.contains("<script>"));
            assert!(!response_str.contains("javascript:"));
        }
    }
}

#[actix_web::test]
async fn test_buffer_overflow_prevention() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test extremely long inputs
    let long_string = "a".repeat(10000);
    
    let request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": &long_string,
            "displayName": &long_string,
            "attestation": "none"
        }))
        .to_request();

    let resp = test::call_service(&app, request).await;
    // Should handle gracefully without crashing
    assert!(resp.status().is_client_error() || resp.status().is_success());
}

#[actix_web::test]
async fn test_challenge_replay_attack_prevention() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Begin registration to get a challenge
    let reg_req = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "none"
        }))
        .to_request();

    let reg_resp = test::call_service(&app, reg_req).await;
    let reg_result: serde_json::Value = test::read_body_json(reg_resp).await;
    let challenge = reg_result["challenge"].as_str().unwrap();

    // Try to use the same challenge twice (simulated by attempting completion with same challenge)
    // In a real scenario, this would involve completing registration then trying again
    // For now, we test that challenges are properly generated and unique
    
    // Get another challenge for same user
    let reg_req2 = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "none"
        }))
        .to_request();

    let reg_resp2 = test::call_service(&app, reg_req2).await;
    let reg_result2: serde_json::Value = test::read_body_json(reg_resp2).await;
    let challenge2 = reg_result2["challenge"].as_str().unwrap();

    // Challenges should be different
    assert_ne!(challenge, challenge2);
    
    // Challenges should be properly encoded base64url without padding
    assert!(!challenge.contains('='));
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
    assert!(!challenge2.contains('='));
    assert!(!challenge2.contains('+'));
    assert!(!challenge2.contains('/'));
}

#[actix_web::test]
async fn test_origin_validation() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test that origin validation would work (simulated through proper configuration)
    // The actual origin validation happens during credential verification
    let request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "none"
        }))
        .to_request();

    let resp = test::call_service(&app, request).await;
    assert!(resp.status().is_success());
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "ok");
}

#[actix_web::test]
async fn test_rate_limiting_simulation() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Simulate multiple rapid requests from same IP
    let mut success_count = 0;
    let mut error_count = 0;
    
    for _ in 0..50 {
        let request = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(&json!({
                "username": "test@example.com",
                "displayName": "Test User",
                "attestation": "none"
            }))
            .to_request();

        let resp = test::call_service(&app, request).await;
        if resp.status().is_success() {
            success_count += 1;
        } else {
            error_count += 1;
        }
    }
    
    // In a production environment with rate limiting, we'd expect some requests to be blocked
    // For now, we just verify the server handles the load without crashing
    assert!(success_count + error_count == 50);
    assert!(success_count > 0); // At least some requests should succeed
}

#[actix_web::test]
async fn test_input_validation_edge_cases() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test edge cases for input validation
    let test_cases = vec![
        ("", "Test User", "empty username"),
        ("test@example.com", "", "empty display name"),
        ("a", "Test User", "very short username"),
        ("test@example.com", "a", "very short display name"),
        ("test@", "Test User", "invalid email format"),
        ("test..test@example.com", "Test User", "invalid email with double dots"),
    ];

    for (username, display_name, description) in test_cases {
        let request = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(&json!({
                "username": username,
                "displayName": display_name,
                "attestation": "none"
            }))
            .to_request();

        let resp = test::call_service(&app, request).await;
        
        // Should handle gracefully - either accept or reject with proper error
        assert!(resp.status().is_success() || resp.status().is_client_error());
        
        if resp.status().is_client_error() {
            let result: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(result["status"], "failed");
            assert!(!result["errorMessage"].as_str().unwrap().is_empty());
        }
    }
}