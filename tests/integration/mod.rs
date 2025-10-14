//! Integration tests

use actix_web::{test, App};
use fido_server::routes::api::configure;

#[actix_web::test]
async fn test_health_endpoint() {
    let app = test::init_service(App::new().configure(configure)).await;
    
    let req = test::TestRequest::get()
        .uri("/api/v1/health")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "healthy");
    assert!(result.get("timestamp").is_some());
}

#[actix_web::test]
async fn test_registration_start_endpoint() {
    let app = test::init_service(App::new().configure(configure)).await;
    
    let req = test::TestRequest::post()
        .uri("/api/v1/webauthn/register/start")
        .set_json(&serde_json::json!({
            "username": "testuser",
            "display_name": "Test User"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert!(result.get("challenge").is_some());
    assert!(result.get("user").is_some());
    assert!(result.get("rp").is_some());
    assert!(result.get("pub_key_cred_params").is_some());
}

#[actix_web::test]
async fn test_registration_finish_endpoint() {
    let app = test::init_service(App::new().configure(configure)).await;
    
    let req = test::TestRequest::post()
        .uri("/api/v1/webauthn/register/finish")
        .set_json(&serde_json::json!({
            "credential": {"id": "test_credential"},
            "session": "test_session"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert!(result.get("credential_id").is_some());
    assert!(result.get("user_id").is_some());
}

#[actix_web::test]
async fn test_authentication_start_endpoint() {
    let app = test::init_service(App::new().configure(configure)).await;
    
    let req = test::TestRequest::post()
        .uri("/api/v1/webauthn/authenticate/start")
        .set_json(&serde_json::json!({
            "username": "testuser"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert!(result.get("challenge").is_some());
    assert!(result.get("rp_id").is_some());
    assert!(result.get("allow_credentials").is_some());
    assert!(result.get("user_verification").is_some());
}

#[actix_web::test]
async fn test_authentication_finish_endpoint() {
    let app = test::init_service(App::new().configure(configure)).await;
    
    let req = test::TestRequest::post()
        .uri("/api/v1/webauthn/authenticate/finish")
        .set_json(&serde_json::json!({
            "credential": {"id": "test_credential"},
            "session": "test_session"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert!(result.get("user_id").is_some());
    assert!(result.get("credential_id").is_some());
}