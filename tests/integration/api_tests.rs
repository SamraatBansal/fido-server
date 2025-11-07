use actix_web::{test, web, App};
use serde_json::json;

use fido_server::{
    config::settings::WebAuthnSettings,
    controllers::registration::AppState,
    routes::api,
    services::WebAuthnService,
};

#[actix_web::test]
async fn test_health_endpoint() {
    let app = test::init_service(
        App::new()
            .configure(api::configure)
    ).await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();
        
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

// Note: These tests require a more complex setup with database and WebAuthn service
// For now, this demonstrates the basic API structure works