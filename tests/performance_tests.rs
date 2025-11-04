//! Performance and load tests for FIDO2/WebAuthn server
//! Tests performance characteristics and load handling

use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fido_server::controllers::WebAuthnController;
use fido_server::webauthn::{WebAuthnConfig, WebAuthnServiceImpl};

#[actix_web::test]
async fn test_single_request_performance() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    let request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "none"
        }))
        .to_request();

    let start = Instant::now();
    let resp = test::call_service(&app, request).await;
    let duration = start.elapsed();

    // Single request should be very fast (< 100ms)
    assert!(duration < Duration::from_millis(100));
    assert!(resp.status().is_success());
    
    println!("Single request took: {:?}", duration);
}

#[actix_web::test]
async fn test_concurrent_registration_requests() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    let concurrent_requests = 100;
    let start = Instant::now();
    
    let handles: Vec<_> = (0..concurrent_requests)
        .map(|i| {
            let app = app.clone();
            tokio::spawn(async move {
                let request = test::TestRequest::post()
                    .uri("/webauthn/attestation/options")
                    .set_json(&json!({
                        "username": format!("user{}@example.com", i),
                        "displayName": format!("User {}", i),
                        "attestation": "none"
                    }))
                    .to_request();

                let req_start = Instant::now();
                let resp = test::call_service(&app, request).await;
                let duration = req_start.elapsed();
                
                (resp.status().is_success(), duration)
            })
        })
        .collect();

    let mut success_count = 0;
    let mut total_duration = Duration::ZERO;
    let mut max_duration = Duration::ZERO;
    let mut min_duration = Duration::from_secs(1);

    for handle in handles {
        let (success, duration) = handle.await.unwrap();
        if success {
            success_count += 1;
        }
        total_duration += duration;
        max_duration = max_duration.max(duration);
        min_duration = min_duration.min(duration);
    }

    let total_time = start.elapsed();
    let avg_duration = total_duration / concurrent_requests as u32;

    // Performance assertions
    assert!(success_count >= concurrent_requests * 95 / 100); // 95% success rate
    assert!(avg_duration < Duration::from_millis(50)); // Average < 50ms
    assert!(max_duration < Duration::from_millis(200)); // Max < 200ms
    assert!(total_time < Duration::from_secs(5)); // Total < 5 seconds

    println!("Concurrent requests ({}) results:", concurrent_requests);
    println!("  Success rate: {}/{} ({}%)", success_count, concurrent_requests, success_count * 100 / concurrent_requests);
    println!("  Average response time: {:?}", avg_duration);
    println!("  Min response time: {:?}", min_duration);
    println!("  Max response time: {:?}", max_duration);
    println!("  Total time: {:?}", total_time);
}

#[actix_web::test]
async fn test_mixed_workload_performance() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // First, create some users by initiating registration
    for i in 0..10 {
        let request = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(&json!({
                "username": format!("user{}@example.com", i),
                "displayName": format!("User {}", i),
                "attestation": "none"
            }))
            .to_request();

        let resp = test::call_service(&app, request).await;
        assert!(resp.status().is_success());
    }

    let mixed_requests = 200;
    let start = Instant::now();
    
    let handles: Vec<_> = (0..mixed_requests)
        .map(|i| {
            let app = app.clone();
            tokio::spawn(async move {
                let is_registration = i % 2 == 0;
                let user_id = i % 10;
                
                let request = if is_registration {
                    test::TestRequest::post()
                        .uri("/webauthn/attestation/options")
                        .set_json(&json!({
                            "username": format!("user{}@example.com", user_id),
                            "displayName": format!("User {}", user_id),
                            "attestation": "none"
                        }))
                        .to_request()
                } else {
                    test::TestRequest::post()
                        .uri("/webauthn/assertion/options")
                        .set_json(&json!({
                            "username": format!("user{}@example.com", user_id),
                            "userVerification": "required"
                        }))
                        .to_request()
                };

                let req_start = Instant::now();
                let resp = test::call_service(&app, request).await;
                let duration = req_start.elapsed();
                
                (resp.status().is_success(), duration, is_registration)
            })
        })
        .collect();

    let mut reg_success = 0;
    let mut auth_success = 0;
    let mut reg_total = Duration::ZERO;
    let mut auth_total = Duration::ZERO;

    for handle in handles {
        let (success, duration, is_registration) = handle.await.unwrap();
        if success {
            if is_registration {
                reg_success += 1;
                reg_total += duration;
            } else {
                auth_success += 1;
                auth_total += duration;
            }
        }
    }

    let total_time = start.elapsed();
    let reg_avg = if reg_success > 0 { reg_total / reg_success as u32 } else { Duration::ZERO };
    let auth_avg = if auth_success > 0 { auth_total / auth_success as u32 } else { Duration::ZERO };

    // Performance assertions for mixed workload
    assert!(reg_success + auth_success >= mixed_requests * 90 / 100); // 90% overall success
    assert!(reg_avg < Duration::from_millis(50)); // Registration avg < 50ms
    assert!(auth_avg < Duration::from_millis(50)); // Authentication avg < 50ms
    assert!(total_time < Duration::from_secs(10)); // Total < 10 seconds

    println!("Mixed workload results:");
    println!("  Registration success: {}/{}", reg_success, mixed_requests / 2);
    println!("  Authentication success: {}/{}", auth_success, mixed_requests / 2);
    println!("  Registration avg time: {:?}", reg_avg);
    println!("  Authentication avg time: {:?}", auth_avg);
    println!("  Total time: {:?}", total_time);
}

#[actix_web::test]
async fn test_memory_usage_stability() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Simulate sustained load over multiple rounds
    let rounds = 5;
    let requests_per_round = 50;
    
    for round in 0..rounds {
        let handles: Vec<_> = (0..requests_per_round)
            .map(|i| {
                let app = app.clone();
                tokio::spawn(async move {
                    let request = test::TestRequest::post()
                        .uri("/webauthn/attestation/options")
                        .set_json(&json!({
                            "username": format!("user{}-round{}@example.com", i, round),
                            "displayName": format!("User {} Round {}", i, round),
                            "attestation": "none"
                        }))
                        .to_request();

                    test::call_service(&app, request).await
                })
            })
            .collect();

        let mut success_count = 0;
        for handle in handles {
            let resp = handle.await.unwrap();
            if resp.status().is_success() {
                success_count += 1;
            }
        }

        // Each round should maintain high success rate
        assert!(success_count >= requests_per_round * 95 / 100);
        println!("Round {}: {}/{} requests successful", round, success_count, requests_per_round);
    }
}

#[actix_web::test]
async fn test_large_payload_handling() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    // Test with large display name
    let large_display_name = "A".repeat(1000);
    
    let request = test::TestRequest::post()
        .uri("/webauthn/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": large_display_name,
            "attestation": "none"
        }))
        .to_request();

    let start = Instant::now();
    let resp = test::call_service(&app, request).await;
    let duration = start.elapsed();

    // Should handle large payloads gracefully
    assert!(duration < Duration::from_millis(200));
    
    if resp.status().is_success() {
        let result: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(result["status"], "ok");
    } else {
        // Should fail gracefully with proper error
        assert!(resp.status().is_client_error());
    }
    
    println!("Large payload handling took: {:?}", duration);
}

#[actix_web::test]
async fn test_challenge_generation_performance() {
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(webauthn_config));
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_controller))
            .configure(fido_server::routes::api::configure)
    ).await;

    let challenge_count = 1000;
    let mut challenges = Vec::new();
    let start = Instant::now();
    
    for i in 0..challenge_count {
        let request = test::TestRequest::post()
            .uri("/webauthn/attestation/options")
            .set_json(&json!({
                "username": format!("user{}@example.com", i),
                "displayName": format!("User {}", i),
                "attestation": "none"
            }))
            .to_request();

        let resp = test::call_service(&app, request).await;
        assert!(resp.status().is_success());
        
        let result: serde_json::Value = test::read_body_json(resp).await;
        let challenge = result["challenge"].as_str().unwrap().to_string();
        challenges.push(challenge);
    }
    
    let total_time = start.elapsed();
    let avg_time = total_time / challenge_count;
    
    // Challenge generation should be fast
    assert!(avg_time < Duration::from_millis(10)); // Average < 10ms per challenge
    assert!(total_time < Duration::from_secs(5)); // Total < 5 seconds
    
    // All challenges should be unique
    let mut unique_challenges = challenges.clone();
    unique_challenges.sort();
    unique_challenges.dedup();
    assert_eq!(challenges.len(), unique_challenges.len());
    
    println!("Challenge generation performance:");
    println!("  Generated {} challenges in {:?}", challenge_count, total_time);
    println!("  Average time per challenge: {:?}", avg_time);
    println!("  All challenges unique: {}", challenges.len() == unique_challenges.len());
}