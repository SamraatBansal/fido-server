//! Authentication integration tests

use actix_test::{self, TestServer};
use actix_web::{http::StatusCode, App};
use fido_server::{routes, configure_app};
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_assertion_options_success() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        });

        let resp = app
            .post("/assertion/options")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "ok");
        assert!(result["challenge"].as_str().is_some());
        assert!(result["rpId"].as_str().is_some());
        assert!(result["allowCredentials"].as_array().is_some());
        assert_eq!(result["userVerification"], "required");
    }

    #[actix_web::test]
    async fn test_assertion_options_missing_username() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "userVerification": "required"
        });

        let resp = app
            .post("/assertion/options")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_assertion_options_user_not_found() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "username": "nonexistent@example.com",
            "userVerification": "required"
        });

        let resp = app
            .post("/assertion/options")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_assertion_result_success() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        // First, get a challenge
        let challenge_request = json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        });

        let challenge_resp = app
            .post("/assertion/options")
            .send_json(&challenge_request)
            .await;

        assert_eq!(challenge_resp.status(), StatusCode::OK);

        // Mock assertion result (simplified for test)
        let request_body = json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/assertion/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "ok");
        assert_eq!(result["errorMessage"], "");
    }

    #[actix_web::test]
    async fn test_assertion_result_missing_credential() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/assertion/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_assertion_result_invalid_signature() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "id": "invalid_credential_id",
            "response": {
                "authenticatorData": "invalid_auth_data",
                "signature": "invalid_signature",
                "userHandle": "",
                "clientDataJSON": "invalid_client_data"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/assertion/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }

    #[actix_web::test]
    async fn test_assertion_result_credential_not_found() {
        let app = TestServer::new(|| {
            App::new().configure(configure_app)
        })
        .await;

        let request_body = json!({
            "id": "nonexistent_credential_id",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let resp = app
            .post("/assertion/result")
            .send_json(&request_body)
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let result: serde_json::Value = resp.json().await;
        assert_eq!(result["status"], "failed");
        assert!(result["errorMessage"].as_str().is_some());
    }
}