//! Integration tests for complete WebAuthn flows

use actix_web::{http::StatusCode, test, App};
use serde_json::json;
use fido_server::routes::api;

use crate::common::{TestDataFactory, ServerResponse};

/// Test application setup
async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new().configure(api::configure)
    ).await
}

#[actix_web::test]
async fn test_complete_registration_flow() {
    let app = create_test_app().await;
    
    // Step 1: Get attestation options
    let attestation_req = TestDataFactory::valid_attestation_options_request();
    let attestation_options_body = json!({
        "username": attestation_req.username,
        "displayName": attestation_req.display_name,
        "attestation": attestation_req.attestation,
        "authenticatorSelection": attestation_req.authenticator_selection
    });

    let attestation_resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&attestation_options_body)
        .send_request(&app)
        .await;

    assert_eq!(attestation_resp.status(), StatusCode::OK);
    let attestation_options: serde_json::Value = test::read_body_json(attestation_resp).await;
    
    // Extract challenge for next step
    let challenge = attestation_options.get("challenge").unwrap().as_str().unwrap();
    let user_id = attestation_options.get("user").unwrap().get("id").unwrap().as_str().unwrap();
    
    assert!(!challenge.is_empty());
    assert!(!user_id.is_empty());

    // Step 2: Submit attestation result
    let attestation_result = TestDataFactory::valid_attestation_result_request();
    let attestation_result_body = json!({
        "id": attestation_result.id,
        "rawId": attestation_result.raw_id,
        "response": {
            "attestationObject": attestation_result.response.attestation_object,
            "clientDataJSON": attestation_result.response.client_data_json
        },
        "type": attestation_result.credential_type
    });

    let result_resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_result_body)
        .send_request(&app)
        .await;

    assert_eq!(result_resp.status(), StatusCode::OK);
    let result: ServerResponse = test::read_body_json(result_resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
}

#[actix_web::test]
async fn test_complete_authentication_flow() {
    let app = create_test_app().await;
    
    // Step 1: Get assertion options
    let assertion_req = TestDataFactory::valid_assertion_options_request();
    let assertion_options_body = json!({
        "username": assertion_req.username,
        "userVerification": assertion_req.user_verification
    });

    let assertion_resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&assertion_options_body)
        .send_request(&app)
        .await;

    assert_eq!(assertion_resp.status(), StatusCode::OK);
    let assertion_options: serde_json::Value = test::read_body_json(assertion_resp).await;
    
    // Extract challenge and credentials for next step
    let challenge = assertion_options.get("challenge").unwrap().as_str().unwrap();
    let allow_credentials = assertion_options.get("allowCredentials").unwrap().as_array().unwrap();
    
    assert!(!challenge.is_empty());
    assert!(!allow_credentials.is_empty());

    // Step 2: Submit assertion result
    let assertion_result = TestDataFactory::valid_assertion_result_request();
    let assertion_result_body = json!({
        "id": assertion_result.id,
        "rawId": assertion_result.raw_id,
        "response": {
            "authenticatorData": assertion_result.response.authenticator_data,
            "clientDataJSON": assertion_result.response.client_data_json,
            "signature": assertion_result.response.signature,
            "userHandle": assertion_result.response.user_handle
        },
        "type": assertion_result.credential_type
    });

    let result_resp = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion_result_body)
        .send_request(&app)
        .await;

    assert_eq!(result_resp.status(), StatusCode::OK);
    let result: ServerResponse = test::read_body_json(result_resp).await;
    assert_eq!(result.status, "ok");
    assert_eq!(result.error_message, "");
}

#[actix_web::test]
async fn test_full_webauthn_ceremony() {
    let app = create_test_app().await;
    let username = "testuser@example.com";
    let display_name = "Test User";
    
    // === Registration Ceremony ===
    
    // 1. Start registration
    let registration_options = json!({
        "username": username,
        "displayName": display_name,
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    });

    let reg_options_resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_options)
        .send_request(&app)
        .await;

    assert_eq!(reg_options_resp.status(), StatusCode::OK);
    let reg_options: serde_json::Value = test::read_body_json(reg_options_resp).await;
    
    let reg_challenge = reg_options.get("challenge").unwrap().as_str().unwrap();
    let rp_id = reg_options.get("rp").unwrap().get("id").unwrap().as_str().unwrap();
    
    // 2. Complete registration
    let registration_result = TestDataFactory::valid_attestation_result_request();
    let registration_completion = json!({
        "id": registration_result.id,
        "rawId": registration_result.raw_id,
        "response": {
            "attestationObject": registration_result.response.attestation_object,
            "clientDataJSON": registration_result.response.client_data_json
        },
        "type": registration_result.credential_type
    });

    let reg_result_resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&registration_completion)
        .send_request(&app)
        .await;

    assert_eq!(reg_result_resp.status(), StatusCode::OK);
    let reg_result: ServerResponse = test::read_body_json(reg_result_resp).await;
    assert_eq!(reg_result.status, "ok");

    // === Authentication Ceremony ===
    
    // 3. Start authentication
    let auth_options = json!({
        "username": username,
        "userVerification": "preferred"
    });

    let auth_options_resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&auth_options)
        .send_request(&app)
        .await;

    assert_eq!(auth_options_resp.status(), StatusCode::OK);
    let auth_options: serde_json::Value = test::read_body_json(auth_options_resp).await;
    
    let auth_challenge = auth_options.get("challenge").unwrap().as_str().unwrap();
    let auth_rp_id = auth_options.get("rpId").unwrap().as_str().unwrap();
    
    // Verify RP ID consistency
    assert_eq!(rp_id, auth_rp_id);
    
    // 4. Complete authentication
    let authentication_result = TestDataFactory::valid_assertion_result_request();
    let authentication_completion = json!({
        "id": authentication_result.id,
        "rawId": authentication_result.raw_id,
        "response": {
            "authenticatorData": authentication_result.response.authenticator_data,
            "clientDataJSON": authentication_result.response.client_data_json,
            "signature": authentication_result.response.signature,
            "userHandle": authentication_result.response.user_handle
        },
        "type": authentication_result.credential_type
    });

    let auth_result_resp = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&authentication_completion)
        .send_request(&app)
        .await;

    assert_eq!(auth_result_resp.status(), StatusCode::OK);
    let auth_result: ServerResponse = test::read_body_json(auth_result_resp).await;
    assert_eq!(auth_result.status, "ok");
}

#[actix_web::test]
async fn test_registration_with_different_attestation_formats() {
    let app = create_test_app().await;
    
    let attestation_formats = vec!["none", "indirect", "direct"];
    
    for format in attestation_formats {
        let attestation_req = json!({
            "username": "user@example.com",
            "displayName": "Test User",
            "attestation": format,
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": false,
                "userVerification": "preferred"
            }
        });

        let resp = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&attestation_req)
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        
        let options: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(options.get("attestation").unwrap().as_str().unwrap(), format);
    }
}

#[actix_web::test]
async fn test_authentication_with_different_user_verification() {
    let app = create_test_app().await;
    
    let verification_levels = vec!["required", "preferred", "discouraged"];
    
    for verification in verification_levels {
        let assertion_req = json!({
            "username": "user@example.com",
            "userVerification": verification
        });

        let resp = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&assertion_req)
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        
        let options: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(options.get("userVerification").unwrap().as_str().unwrap(), verification);
    }
}

#[actix_web::test]
async fn test_cross_platform_authenticator_selection() {
    let app = create_test_app().await;
    
    let attestation_req = json!({
        "username": "user@example.com",
        "displayName": "Cross-platform User",
        "attestation": "none",
        "authenticatorSelection": {
            "authenticatorAttachment": "cross-platform",
            "requireResidentKey": true,
            "userVerification": "required"
        }
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&attestation_req)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    
    let options: serde_json::Value = test::read_body_json(resp).await;
    let auth_selection = options.get("authenticatorSelection").unwrap();
    
    assert_eq!(
        auth_selection.get("authenticatorAttachment").unwrap().as_str().unwrap(),
        "cross-platform"
    );
    assert_eq!(
        auth_selection.get("requireResidentKey").unwrap().as_bool().unwrap(),
        true
    );
    assert_eq!(
        auth_selection.get("userVerification").unwrap().as_str().unwrap(),
        "required"
    );
}

#[actix_web::test]
async fn test_platform_authenticator_selection() {
    let app = create_test_app().await;
    
    let attestation_req = json!({
        "username": "user@example.com",
        "displayName": "Platform User",
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": false,
            "userVerification": "preferred"
        }
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&attestation_req)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    
    let options: serde_json::Value = test::read_body_json(resp).await;
    let auth_selection = options.get("authenticatorSelection").unwrap();
    
    assert_eq!(
        auth_selection.get("authenticatorAttachment").unwrap().as_str().unwrap(),
        "platform"
    );
    assert_eq!(
        auth_selection.get("requireResidentKey").unwrap().as_bool().unwrap(),
        false
    );
    assert_eq!(
        auth_selection.get("userVerification").unwrap().as_str().unwrap(),
        "preferred"
    );
}

#[actix_web::test]
async fn test_state_persistence_verification() {
    let app = create_test_app().await;
    
    // Register a user
    let username = "persistent@example.com";
    let registration_req = json!({
        "username": username,
        "displayName": "Persistent User",
        "attestation": "direct"
    });

    let reg_resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_req)
        .send_request(&app)
        .await;

    assert_eq!(reg_resp.status(), StatusCode::OK);
    
    // Try to authenticate the same user
    let auth_req = json!({
        "username": username,
        "userVerification": "preferred"
    });

    let auth_resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&auth_req)
        .send_request(&app)
        .await;

    assert_eq!(auth_resp.status(), StatusCode::OK);
    
    let auth_options: serde_json::Value = test::read_body_json(auth_resp).await;
    let allow_credentials = auth_options.get("allowCredentials").unwrap().as_array().unwrap();
    
    // Should have credentials available for the registered user
    assert!(!allow_credentials.is_empty());
}

#[actix_web::test]
async fn test_concurrent_requests() {
    let app = create_test_app().await;
    
    // Send multiple concurrent requests
    let mut handles = vec![];
    
    for i in 0..10 {
        let app_clone = app.clone();
        let handle = tokio::spawn(async move {
            let req = json!({
                "username": format!("user{}@example.com", i),
                "displayName": format!("User {}", i),
                "attestation": "none"
            });

            let resp = test::TestRequest::post()
                .uri("/attestation/options")
                .set_json(&req)
                .send_request(&app_clone)
                .await;

            resp.status()
        });
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    for handle in handles {
        let status = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK);
    }
}

#[actix_web::test]
async fn test_error_propagation() {
    let app = create_test_app().await;
    
    // Test various error scenarios and ensure proper error propagation
    
    // 1. Non-existent user authentication
    let auth_req = json!({
        "username": "nonexistent@example.com",
        "userVerification": "preferred"
    });

    let auth_resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&auth_req)
        .send_request(&app)
        .await;

    // Should handle gracefully (either return empty credentials or error)
    assert!(auth_resp.status() == StatusCode::OK || auth_resp.status() == StatusCode::BAD_REQUEST);
    
    if auth_resp.status() == StatusCode::BAD_REQUEST {
        let error: ServerResponse = test::read_body_json(auth_resp).await;
        assert_eq!(error.status, "failed");
        assert!(!error.error_message.is_empty());
    }
}

#[actix_web::test]
async fn test_timeout_configuration() {
    let app = create_test_app().await;
    
    let attestation_req = json!({
        "username": "timeout@example.com",
        "displayName": "Timeout Test"
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&attestation_req)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    
    let options: serde_json::Value = test::read_body_json(resp).await;
    let timeout = options.get("timeout").unwrap().as_u64().unwrap();
    
    // Should have a reasonable timeout (between 30 seconds and 10 minutes)
    assert!(timeout >= 30000 && timeout <= 600000);
}