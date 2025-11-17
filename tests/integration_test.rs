use serde_json::json;
use tokio::net::TcpListener;

use fido_server::{
    handlers::AppState,
    memory_db::MemoryDatabase,
    simple_webauthn::SimpleWebAuthnService,
    types::*,
};

use axum::{
    extract::DefaultBodyLimit,
    http::{
        header::{CONTENT_TYPE},
        Method, StatusCode,
    },
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    timeout::TimeoutLayer,
};
use std::time::Duration;

async fn create_test_app() -> Router {
    let db = MemoryDatabase::new();
    let rp_id = "localhost";
    let origin = url::Url::parse("http://localhost:8080").unwrap();
    let rp_name = "Test Corporation";
    
    let webauthn_service = SimpleWebAuthnService::new(rp_id, &origin, rp_name, db).unwrap();
    
    let app_state = AppState {
        webauthn: webauthn_service,
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:8080".parse().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE])
        .allow_credentials(true);

    Router::new()
        .route("/health", get(fido_server::handlers::health))
        .route("/attestation/options", post(fido_server::handlers::attestation_options))
        .route("/attestation/result", post(fido_server::handlers::attestation_result))
        .route("/assertion/options", post(fido_server::handlers::assertion_options))
        .route("/assertion/result", post(fido_server::handlers::assertion_result))
        .fallback(fido_server::handlers::handler_404)
        .layer(
            ServiceBuilder::new()
                .layer(cors)
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .layer(DefaultBodyLimit::max(1024 * 1024))
        )
        .with_state(app_state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = create_test_app().await;
    
    let response = axum_test::TestServer::new(app)
        .unwrap()
        .get("/health")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "FIDO2 WebAuthn Server");
}

#[tokio::test]
async fn test_attestation_options() {
    let app = create_test_app().await;
    
    let request_body = json!({
        "username": "testuser@example.com",
        "displayName": "Test User",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let response = axum_test::TestServer::new(app)
        .unwrap()
        .post("/attestation/options")
        .json(&request_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    
    let body: ServerPublicKeyCredentialCreationOptionsResponse = response.json();
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
    assert_eq!(body.rp.name, "Test Corporation");
    assert_eq!(body.user.name, "testuser@example.com");
    assert_eq!(body.user.display_name, "Test User");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.timeout, 10000);
}

#[tokio::test]
async fn test_attestation_result_with_invalid_data() {
    let app = create_test_app().await;
    
    let request_body = json!({
        "id": "test-credential-id",
        "response": {
            "clientDataJSON": "invalid-base64",
            "attestationObject": "invalid-base64"
        },
        "type": "public-key",
        "getClientExtensionResults": {}
    });

    let response = axum_test::TestServer::new(app)
        .unwrap()
        .post("/attestation/result")
        .json(&request_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    let body: ServerResponse = response.json();
    assert_eq!(body.status, "failed");
    assert!(!body.error_message.is_empty());
}

#[tokio::test]
async fn test_assertion_options_user_not_found() {
    let app = create_test_app().await;
    
    let request_body = json!({
        "username": "nonexistent@example.com",
        "userVerification": "required"
    });

    let response = axum_test::TestServer::new(app)
        .unwrap()
        .post("/assertion/options")
        .json(&request_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    
    let body: ServerResponse = response.json();
    assert_eq!(body.status, "failed");
    assert_eq!(body.error_message, "User does not exist!");
}

#[tokio::test] 
async fn test_assertion_result_with_invalid_data() {
    let app = create_test_app().await;
    
    let request_body = json!({
        "id": "test-credential-id",
        "response": {
            "clientDataJSON": "invalid-base64",
            "authenticatorData": "invalid-base64",
            "signature": "invalid-base64",
            "userHandle": null
        },
        "type": "public-key",
        "getClientExtensionResults": {}
    });

    let response = axum_test::TestServer::new(app)
        .unwrap()
        .post("/assertion/result")
        .json(&request_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    
    let body: ServerResponse = response.json();
    assert_eq!(body.status, "failed");
    assert!(!body.error_message.is_empty());
}

#[tokio::test]
async fn test_404_handler() {
    let app = create_test_app().await;
    
    let response = axum_test::TestServer::new(app)
        .unwrap()
        .get("/nonexistent")
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    
    let body: ServerResponse = response.json();
    assert_eq!(body.status, "failed");
    assert_eq!(body.error_message, "Endpoint not found");
}