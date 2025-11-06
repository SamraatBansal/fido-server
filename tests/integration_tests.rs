use actix_web::{test, web, App};
use fido2_webauthn_server::*;
use serde_json::json;
use std::sync::Arc;

async fn setup_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
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

    test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
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
            .route("/health", web::get().to(health_check)),
    )
    .await
}

#[actix_rt::test]
async fn test_health_check() {
    let app = setup_test_app().await;
    
    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
}

#[actix_rt::test]
async fn test_registration_flow() {
    let app = setup_test_app().await;
    
    // Test registration options request
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "username": "testuser",
            "displayName": "Test User",
            "attestation": "direct"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    
    let body: ServerPublicKeyCredentialCreationOptionsResponse = test::read_body_json(resp).await;
    assert_eq!(body.base.status, "ok");
    assert!(!body.challenge.is_empty());
    assert_eq!(body.user.name, "testuser");
    assert_eq!(body.user.display_name, "Test User");
    assert!(!body.pub_key_cred_params.is_empty());
    
    // Verify extensions are included
    assert!(body.extensions.is_some());
    let extensions = body.extensions.unwrap();
    assert!(extensions.contains_key("example.extension"));
}

#[actix_rt::test]
async fn test_registration_validation() {
    let app = setup_test_app().await;
    
    // Test missing username
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "displayName": "Test User"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    
    // Test missing displayName
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "username": "testuser"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    
    // Test empty username
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "username": "",
            "displayName": "Test User"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_rt::test]
async fn test_attestation_response_validation() {
    let app = setup_test_app().await;
    
    // Test missing id field
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJ0ZXN0IjoidGVzdCJ9",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAFAC7NS4FyVcBGGGtS6YlQC4WsLVCRrQCXRFpFz-ckhGnM5AAHFHkJX_o1ILJg"
            }
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    
    // Test invalid type
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "id": "dGVzdA",
            "type": "invalid-type",
            "response": {
                "clientDataJSON": "eyJ0ZXN0IjoidGVzdCJ9",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAFAC7NS4FyVcBGGGtS6YlQC4WsLVCRrQCXRFpFz-ckhGnM5AAHFHkJX_o1ILJg"
            }
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    
    // Test empty clientDataJSON
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "id": "dGVzdA",
            "type": "public-key",
            "response": {
                "clientDataJSON": "",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAFAC7NS4FyVcBGGGtS6YlQC4WsLVCRrQCXRFpFz-ckhGnM5AAHFHkJX_o1ILJg"
            }
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    
    // Test empty attestationObject
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "id": "dGVzdA",
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJ0ZXN0IjoidGVzdCJ9",
                "attestationObject": ""
            }
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_rt::test]
async fn test_authentication_user_not_found() {
    let app = setup_test_app().await;
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&json!({
            "username": "nonexistentuser"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
    
    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
    assert!(!body.error_message.is_empty());
}

#[actix_rt::test] 
async fn test_assertion_response_validation() {
    let app = setup_test_app().await;
    
    // Test missing signature field
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&json!({
            "id": "dGVzdA",
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJ0ZXN0IjoidGVzdCJ9",
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "userHandle": ""
            }
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    
    // Test empty authenticatorData
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&json!({
            "id": "dGVzdA", 
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJ0ZXN0IjoidGVzdCJ9",
                "authenticatorData": "",
                "signature": "dGVzdA",
                "userHandle": ""
            }
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}