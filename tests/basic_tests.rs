//! Basic integration tests

use actix_web::{test, web, App};

#[actix_web::test]
async fn test_health_check() {
    let app = test::init_service(
        App::new().configure(fido_server::routes::api::configure_api)
    ).await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].as_str().is_some());
}