//! API endpoint integration tests

#[cfg(test)]
mod tests {
    use actix_web::{test, App};
    use fido_server::routes::api::configure;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        let req = test::TestRequest::get()
            .uri("/health")
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn test_registration_start_endpoint() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "display_name": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn test_authentication_start_endpoint() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        let req = test::TestRequest::post()
            .uri("/api/v1/authenticate/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        // Should return 404 for non-existent user
        assert_eq!(resp.status(), 404);
    }
}