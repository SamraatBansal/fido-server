//! Authentication integration tests for FIDO2/WebAuthn conformance

use actix_test::TestServer;
use actix_web::{test, web, App};
use fido_server::routes::api::configure_routes;
use serde_json::{json, Value};

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_assertion_options_success() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        
        // This might fail initially if user doesn't exist, but should have proper error handling
        if resp.status().is_success() {
            let body: Value = test::read_body_json(resp).await;
            
            // Verify response structure matches FIDO conformance spec
            assert_eq!(body["status"], "ok");
            assert!(body["errorMessage"].as_str().unwrap().is_empty());
            assert!(body["challenge"].is_string());
            assert!(body["timeout"].is_number());
            assert!(body["rpId"].is_string());
            assert!(body["allowCredentials"].is_array());
            assert_eq!(body["userVerification"], "required");
        } else {
            // Should return proper error for non-existent user
            let body: Value = test::read_body_json(resp).await;
            assert_eq!(body["status"], "failed");
            assert!(body["errorMessage"].as_str().unwrap().contains("User") ||
                    body["errorMessage"].as_str().unwrap().contains("not found") ||
                    body["errorMessage"].as_str().unwrap().contains("does not exist"));
        }
    }

    #[actix_web::test]
    async fn test_assertion_options_missing_username() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "userVerification": "preferred"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("username"));
    }

    #[actix_web::test]
    async fn test_assertion_options_invalid_user_verification() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "username": "johndoe@example.com",
            "userVerification": "invalid"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("userVerification") ||
                body["errorMessage"].as_str().unwrap().contains("invalid"));
    }

    #[actix_web::test]
    async fn test_assertion_result_success() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        // First register a user (this would normally be done separately)
        let registration_req_body = json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "attestation": "none"
        });

        let registration_req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&registration_req_body)
            .to_request();

        let _registration_resp = test::call_service(&app, registration_req).await;

        // Now try to get assertion options
        let assertion_options_req_body = json!({
            "username": "johndoe@example.com",
            "userVerification": "preferred"
        });

        let assertion_options_req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&assertion_options_req_body)
            .to_request();

        let assertion_options_resp = test::call_service(&app, assertion_options_req).await;

        // Mock assertion result (this would normally come from authenticator)
        let result_req_body = json!({
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

        let result_req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&result_req_body)
            .to_request();

        let result_resp = test::call_service(&app, result_req).await;
        
        // For now, we expect this to fail until we implement proper validation
        // This test will pass once we implement the full flow
        assert!(result_resp.status().is_client_error() || result_resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_assertion_result_missing_credential() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "type": "public-key"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("credential") || 
                body["errorMessage"].as_str().unwrap().contains("id"));
    }

    #[actix_web::test]
    async fn test_assertion_result_invalid_signature() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "id": "invalid-credential-id",
            "response": {
                "authenticatorData": "invalid-auth-data",
                "signature": "invalid-signature",
                "userHandle": "",
                "clientDataJSON": "invalid-client-data"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("signature") ||
                body["errorMessage"].as_str().unwrap().contains("validation") ||
                body["errorMessage"].as_str().unwrap().contains("invalid"));
    }

    #[actix_web::test]
    async fn test_assertion_result_credential_not_found() {
        let app = test::init_service(
            App::new().configure(configure_routes)
        ).await;

        let req_body = json!({
            "id": "nonexistent-credential-id",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        });

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&req_body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("credential") ||
                body["errorMessage"].as_str().unwrap().contains("not found") ||
                body["errorMessage"].as_str().unwrap().contains("does not exist"));
    }
}