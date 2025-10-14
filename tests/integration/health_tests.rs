//! Health check integration tests

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