//! Debug test to understand API behavior

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};
    use fido2_webauthn_server::routes::api::configure;
    use fido2_webauthn_server::services::{WebAuthnService, UserService};
    use serde_json::json;

    #[actix_web::test]
    async fn test_debug_attestation_options() {
        // Create services
        let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
            .expect("Failed to create WebAuthn service");
        let user_service = UserService::new();

        // Create test app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service))
                .app_data(web::Data::new(user_service))
                .configure(configure)
        ).await;

        // Test minimal valid request
        let request = json!({
            "username": "test@example.com",
            "displayName": "Test User"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        
        println!("Status: {}", resp.status());
        
        let body_bytes = test::read_body(resp).await;
        let body_str = String::from_utf8_lossy(&body_bytes);
        println!("Response body: {}", body_str);
        
        // Just check it's not a server error
        assert!(resp.status() != 500);
    }
}