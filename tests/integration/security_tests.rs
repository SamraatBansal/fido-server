//! Security integration tests

#[cfg(test)]
mod tests {
    use actix_web::{test, App, http};
    use fido_server::routes::api::configure;

    #[tokio::test]
    async fn test_registration_with_invalid_data() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // Test with invalid email
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "invalid-email",
                "display_name": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        // Test with empty display name
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "display_name": ""
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        // Test with missing fields
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_registration_with_oversized_data() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // Test with very long username
        let long_username = "a".repeat(300) + "@example.com";
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": long_username,
                "display_name": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        // Test with very long display name
        let long_display_name = "a".repeat(300);
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "display_name": long_display_name
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_authentication_with_nonexistent_user() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        let req = test::TestRequest::post()
            .uri("/api/v1/authenticate/start")
            .set_json(&serde_json::json!({
                "username": "nonexistent@example.com"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_registration_finish_with_invalid_challenge() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        let req = test::TestRequest::post()
            .uri("/api/v1/register/finish")
            .set_json(&serde_json::json!({
                "challenge_id": "nonexistent-challenge",
                "credential": {
                    "id": "test-credential-id",
                    "raw_id": "dGVzdC1jcmVkZW50aWFsLWlk",
                    "type": "public-key",
                    "response": {
                        "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="
                    }
                }
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_authentication_finish_with_invalid_challenge() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        let req = test::TestRequest::post()
            .uri("/api/v1/authenticate/finish")
            .set_json(&serde_json::json!({
                "challenge_id": "nonexistent-challenge",
                "credential": {
                    "id": "test-credential-id",
                    "raw_id": "dGVzdC1jcmVkZW50aWFsLWlk",
                    "type": "public-key",
                    "response": {
                        "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ==",
                        "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",
                        "signature": "MEUCIQCdwBCYm5PjT_Q-wwOuyRvEYR_8f2vHqGhJp3b7b8jwIgYKqL8xRf9N8f2vHqGhJp3b7b8jwYKqL8xRf9N8f2vHqGhJp3b7b8jw",
                        "user_handle": null
                    }
                }
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_malformed_json_requests() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // Test with malformed JSON
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_payload("{invalid json}")
            .insert_header((http::header::CONTENT_TYPE, "application/json"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        
        // Test with wrong content type
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_payload("{\"username\":\"test@example.com\"}")
            .insert_header((http::header::CONTENT_TYPE, "text/plain"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_unsupported_http_methods() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // Test GET on registration start (should be POST)
        let req = test::TestRequest::get()
            .uri("/api/v1/register/start")
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 405); // Method Not Allowed
        
        // Test PUT on authentication start (should be POST)
        let req = test::TestRequest::put()
            .uri("/api/v1/authenticate/start")
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 405); // Method Not Allowed
    }

    #[tokio::test]
    async fn test_sql_injection_attempts() {
        let app = test::init_service(App::new().configure(configure)).await;
        
        // Test SQL injection in username
        let malicious_username = "test@example.com'; DROP TABLE users; --";
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": malicious_username,
                "display_name": "Test User"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        // Should be rejected due to invalid email format
        assert_eq!(resp.status(), 400);
        
        // Test SQL injection in display name
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(&serde_json::json!({
                "username": "test@example.com",
                "display_name": "Test User'; DROP TABLE users; --"
            }))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        // Should be accepted (display name allows special chars) but sanitized
        assert!(resp.status().is_success());
    }
}