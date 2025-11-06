use actix_web::{test, web, App};
use fido2_webauthn_server::*;
use serde_json::json;
use std::sync::Arc;

async fn setup_test_app() -> actix_web::test::TestServer {
    // Use in-memory database for tests
    let db_pool = Arc::new(establish_connection_pool());
    
    // Run migrations
    run_migrations(&db_pool).expect("Failed to run migrations");

    // Initialize WebAuthn service
    let webauthn_service = WebAuthnService::new(
        "localhost",
        "FIDO2 Test Server",
        "http://localhost:8080",
        db_pool,
    )
    .expect("Failed to initialize WebAuthn service");

    test::start(move || {
        App::new()
            .app_data(web::Data::new(webauthn_service.clone()))
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(start_registration))
                    .route("/result", web::post().to(finish_registration)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(start_authentication))
                    .route("/result", web::post().to(finish_authentication)),
            )
            .route("/health", web::get().to(health_check))
    })
}

#[actix_rt::test]
async fn test_health_check() {
    let srv = setup_test_app().await;
    
    let mut app = test::TestServer::new(srv);
    let req = app
        .get("/health");
    
    let resp = app.block_on(req);
    assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn test_registration_flow() {
    let srv = setup_test_app().await;
    let mut app = test::TestServer::new(srv);
    
    // Test registration options request
    let req = app
        .post("/attestation/options")
        .set_json(&json!({
            "username": "testuser",
            "displayName": "Test User",
            "attestation": "direct"
        }));
    
    let resp = app.block_on(req);
    assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn test_registration_validation() {
    let srv = setup_test_app().await;
    let mut app = test::TestServer::new(srv);
    
    // Test missing username
    let req = app
        .post("/attestation/options")
        .set_json(&json!({
            "displayName": "Test User"
        }));
    
    let resp = app.block_on(req);
    assert!(resp.status().is_client_error());
}

#[actix_rt::test]
async fn test_authentication_user_not_found() {
    let srv = setup_test_app().await;
    let mut app = test::TestServer::new(srv);
    
    let req = app
        .post("/assertion/options")
        .set_json(&json!({
            "username": "nonexistentuser"
        }));
    
    let resp = app.block_on(req);
    assert!(resp.status().is_client_error());
}