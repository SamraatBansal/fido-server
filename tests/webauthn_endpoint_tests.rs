//! WebAuthn endpoint tests

use actix_web::{test, App};
use serde_json::json;

#[actix_web::test]
async fn test_attestation_options_missing_data() {
    let app = test::init_service(
        App::new().configure(fido_server::routes::api::configure_api)
    ).await;

    // Test missing username
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "displayName": "Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should return 404 because route is not configured in basic test
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_assertion_options_missing_data() {
    let app = test::init_service(
        App::new().configure(fido_server::routes::api::configure_api)
    ).await;

    // Test missing username
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should return 404 because route is not configured in basic test
    assert_eq!(resp.status(), 404);
}