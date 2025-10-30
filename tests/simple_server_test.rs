//! Simple server integration tests

use actix_web::{test, web, App};
use fido_server::simple_server::{configure_routes, SimpleState};

#[actix_web::test]
async fn test_health_endpoint() {
    let state = web::Data::new(SimpleState::new());
    let app = test::init_service(
        App::new()
            .app_data(state)
            .configure(configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
}

#[actix_web::test]
async fn test_registration_options() {
    let state = web::Data::new(SimpleState::new());
    let app = test::init_service(
        App::new()
            .app_data(state)
            .configure(configure_routes)
    ).await;

    let request = serde_json::json!({
        "username": "test@example.com",
        "displayName": "Test User",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["rp"]["name"], "FIDO Server");
    assert_eq!(body["user"]["name"], "test@example.com");
    assert_eq!(body["user"]["displayName"], "Test User");
    assert!(body["challenge"].is_string());
    assert!(body["pubKeyCredParams"].is_array());
}

#[actix_web::test]
async fn test_registration_options_invalid_input() {
    let state = web::Data::new(SimpleState::new());
    let app = test::init_service(
        App::new()
            .app_data(state)
            .configure(configure_routes)
    ).await;

    let request = serde_json::json!({
        "username": "",
        "displayName": "Test User"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["error_message"].as_str().unwrap().contains("Username"));
}

#[actix_web::test]
async fn test_authentication_options_user_not_found() {
    let state = web::Data::new(SimpleState::new());
    let app = test::init_service(
        App::new()
            .app_data(state)
            .configure(configure_routes)
    ).await;

    let request = serde_json::json!({
        "username": "nonexistent@example.com"
    });

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::NOT_FOUND);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["error_message"].as_str().unwrap().contains("User not found"));
}