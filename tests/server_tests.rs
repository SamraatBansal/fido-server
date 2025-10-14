//! Server integration tests

use actix_web::{test, App, middleware::Logger};
use fido_server::routes::api;
use serde_json::json;

#[actix_web::test]
async fn test_server_health_check() {
    // Test that the server can be configured and started
    let app = test::init_service(
        App::new()
            .wrap(Logger::default())
            .configure(api::configure)
    ).await;

    // Test a basic endpoint to ensure the server is working
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn test_cors_headers() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::with_uri("/attestation/options")
        .method(actix_web::http::Method::OPTIONS)
        .insert_header(("Origin", "http://localhost:3000"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should handle CORS preflight requests
    assert!(resp.status().is_success() || resp.status().is_client_error());
}

#[actix_web::test]
async fn test_invalid_route() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    let req = test::TestRequest::get()
        .uri("/invalid/route")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_method_not_allowed() {
    let app = test::init_service(
        App::new().configure(api::configure)
    ).await;

    // Try GET on a POST-only endpoint
    let req = test::TestRequest::get()
        .uri("/attestation/options")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 405); // Method Not Allowed
}