//! Integration tests for the FIDO server

use actix_web::{test, web, App};
use fido_server::{routes::api, AppState};
use fido_server::config::Settings;

#[actix_web::test]
async fn test_registration_start() {
    let settings = Settings::new().expect("Failed to create settings");
    
    let app_state = AppState::new(&settings).expect("Failed to create app state");
    
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/registration/start")
        .set_json(&serde_json::json!({
            "username": "testuser",
            "display_name": "Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_authentication_start_missing_user() {
    let settings = Settings::new().expect("Failed to create settings");
    let app_state = AppState::new(&settings).expect("Failed to create app state");
    
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .configure(api::configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/authentication/start")
        .set_json(&serde_json::json!({
            "username": "nonexistentuser"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 404);
}