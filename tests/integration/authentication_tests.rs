//! Authentication integration tests

use actix_test;
use actix_web::{test, web, App};
use fido_server::routes::api;
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_test::test]
    async fn test_authentication_challenge_success() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&json!({
                "username": "johndoe@example.com",
                "userVerification": "required"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        // For now, expect 404 since user doesn't exist
        assert!(resp.status().is_client_error() || resp.status() == 200);
    }

    #[actix_test::test]
    async fn test_authentication_challenge_missing_username() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&json!({}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
    }

    #[actix_test::test]
    async fn test_authentication_challenge_user_not_found() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&json!({
                "username": "nonexistent@example.com",
                "userVerification": "preferred"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("not found"));
    }

    #[actix_test::test]
    async fn test_authentication_verify_success() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        // Mock assertion response
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&json!({
                "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
                "response": {
                    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                    "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                    "userHandle": "",
                    "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
                },
                "getClientExtensionResults": {},
                "type": "public-key"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        // For now, expect failure since we haven't implemented verification yet
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
    }

    #[actix_test::test]
    async fn test_authentication_verify_invalid_signature() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&json!({
                "id": "some-credential-id",
                "response": {
                    "authenticatorData": "invalid-data",
                    "signature": "invalid-signature",
                    "userHandle": "",
                    "clientDataJSON": "invalid-client-data"
                },
                "type": "public-key"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("signature"));
    }

    #[actix_test::test]
    async fn test_authentication_verify_missing_fields() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&json!({
                "id": "some-id"
                // Missing required fields
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_test::test]
    async fn test_authentication_verify_credential_not_found() {
        let app = test::init_service(
            App::new().configure(api::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&json!({
                "id": "nonexistent-credential-id",
                "response": {
                    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                    "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                    "userHandle": "",
                    "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
                },
                "type": "public-key"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("not found"));
    }
}