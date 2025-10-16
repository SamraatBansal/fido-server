#[actix_web::test]
async fn test_simple_request() {
    let webauthn_service = create_test_app().await;
    let app = test::init_service(
        App::new().service(configure_routes(webauthn_service))
    ).await;

    // Test with minimal JSON
    let req = test::TestRequest::post()
        .uri("/api/attestation/options")
        .set_json(json!({
            "username": "test@example.com",
            "displayName": "Test User"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("Status: {}", resp.status());
    
    assert_eq!(resp.status(), StatusCode::OK);
}