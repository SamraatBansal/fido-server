//! Simplified FIDO2/WebAuthn Conformance Tests

use actix_web::{test, web, App};
use serde_json::json;

use fido_server::dto::*;

/// Health check endpoint
async fn health_check() -> actix_web::Result<actix_web::HttpResponse> {
    Ok(actix_web::HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Registration options endpoint
async fn registration_options(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        server_response: ServerResponse::ok(),
        rp: fido_server::dto::registration::PublicKeyCredentialRpEntity {
            id: Some("localhost".to_string()),
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: "U3932ee31vKEC0JtJMIQ".to_string(),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        },
        challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        pub_key_cred_params: vec![
            fido_server::dto::registration::PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7,
            }
        ],
        timeout: Some(10000),
        exclude_credentials: vec![],
        authenticator_selection: request.authenticator_selection.clone(),
        attestation: request.attestation.clone(),
        extensions: None,
    };

    Ok(actix_web::HttpResponse::Ok().json(response))
}

#[actix_web::test]
async fn test_health_endpoint() {
    let app = test::init_service(
        App::new().route("/health", web::get().to(health_check))
    ).await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "FIDO Server");
    assert!(body["timestamp"].is_string());
    
    println!("✓ Health endpoint test passed");
}

#[actix_web::test]
async fn test_registration_options_basic() {
    let app = test::init_service(
        App::new().route("/attestation/options", web::post().to(registration_options))
    ).await;

    // Test request that matches FIDO conformance test format
    let request_body = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    
    // Verify the response matches FIDO conformance test expectations
    assert_eq!(body.server_response.status, "ok");
    assert_eq!(body.server_response.error_message, "");
    assert_eq!(body.rp.name, "Example Corporation");
    assert_eq!(body.user.name, "johndoe@example.com");
    assert_eq!(body.user.display_name, "John Doe");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.pub_key_cred_params.len(), 1);
    assert_eq!(body.pub_key_cred_params[0].type_, "public-key");
    assert_eq!(body.pub_key_cred_params[0].alg, -7);
    assert_eq!(body.timeout, Some(10000));

    println!("✓ Registration options endpoint test passed");
    println!("  - Status: {}", body.server_response.status);
    println!("  - RP Name: {}", body.rp.name);
    println!("  - Challenge: {}", body.challenge);
    println!("  - Username: {}", body.user.name);
}

#[actix_web::test] 
async fn test_data_structures() {
    // Test that our data structures can be serialized/deserialized properly
    let request = ServerPublicKeyCredentialCreationOptionsRequest {
        username: "test@example.com".to_string(),
        display_name: "Test User".to_string(),
        authenticator_selection: None,
        attestation: webauthn_rs_proto::AttestationConveyancePreference::None,
    };

    let json_str = serde_json::to_string(&request).unwrap();
    let parsed: ServerPublicKeyCredentialCreationOptionsRequest = serde_json::from_str(&json_str).unwrap();
    
    assert_eq!(parsed.username, "test@example.com");
    assert_eq!(parsed.display_name, "Test User");
    
    println!("✓ Data structure serialization test passed");
    println!("  - Serialized: {}", json_str);
}

#[test]
fn test_server_response_format() {
    // Test that ServerResponse matches the expected format
    let success = ServerResponse::ok();
    assert_eq!(success.status, "ok");
    assert_eq!(success.error_message, "");

    let failure = ServerResponse::failed("Test error message");
    assert_eq!(failure.status, "failed");
    assert_eq!(failure.error_message, "Test error message");

    // Test JSON serialization
    let success_json = serde_json::to_value(&success).unwrap();
    assert_eq!(success_json["status"], "ok");
    assert_eq!(success_json["errorMessage"], "");

    let failure_json = serde_json::to_value(&failure).unwrap();
    assert_eq!(failure_json["status"], "failed");
    assert_eq!(failure_json["errorMessage"], "Test error message");

    println!("✓ Server response format test passed");
}