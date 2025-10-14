//! Unit tests for WebAuthn attestation (registration) endpoints

use crate::common::{
    constants,
    helpers::{assert_failed_response, assert_success_response, post_json, response_json},
    security,
    TestDataFactory,
};
use actix_web::{http::StatusCode, test};
use serde_json::json;

/// Test module for POST /attestation/options endpoint
#[cfg(test)]
mod attestation_options_tests {
    use super::*;

    #[actix_web::test]
    async fn test_attestation_options_success() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = TestDataFactory::valid_attestation_options_request();
        let resp = post_json(&app, "/attestation/options", json!(request)).await;

        assert_eq!(resp.status(), StatusCode::OK);
        
        let response: crate::common::AttestationOptionsResponse = 
            response_json(resp).await.unwrap();
        
        assert_success_response(&crate::common::ServerResponse {
            status: response.status.clone(),
            errorMessage: response.errorMessage.clone(),
        });
        
        // Verify required fields
        assert!(!response.challenge.is_empty());
        assert_eq!(response.rp.id, constants::TEST_RP_ID);
        assert_eq!(response.rp.name, constants::TEST_RP_NAME);
        assert_eq!(response.user.name, constants::TEST_USERNAME);
        assert_eq!(response.user.displayName, constants::TEST_DISPLAY_NAME);
        assert!(!response.pubKeyCredParams.is_empty());
        assert!(response.timeout > 0);
        assert_eq!(response.attestation, "direct");
    }

    #[actix_web::test]
    async fn test_attestation_options_missing_username() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = TestDataFactory::invalid_attestation_options_request_no_username();
        let resp = post_json(&app, "/attestation/options", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "username");
    }

    #[actix_web::test]
    async fn test_attestation_options_missing_display_name() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "username": constants::TEST_USERNAME,
            "attestation": "direct"
        });
        let resp = post_json(&app, "/attestation/options", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "displayName");
    }

    #[actix_web::test]
    async fn test_attestation_options_invalid_attestation_value() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "username": constants::TEST_USERNAME,
            "displayName": constants::TEST_DISPLAY_NAME,
            "attestation": "invalid_value"
        });
        let resp = post_json(&app, "/attestation/options", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "attestation");
    }

    #[actix_web::test]
    async fn test_attestation_options_invalid_user_verification() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "username": constants::TEST_USERNAME,
            "displayName": constants::TEST_DISPLAY_NAME,
            "authenticatorSelection": {
                "userVerification": "invalid_value"
            }
        });
        let resp = post_json(&app, "/attestation/options", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "userVerification");
    }

    #[actix_web::test]
    async fn test_attestation_options_oversized_username() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "username": TestDataFactory::oversized_string(),
            "displayName": constants::TEST_DISPLAY_NAME
        });
        let resp = post_json(&app, "/attestation/options", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "username");
    }

    #[actix_web::test]
    async fn test_attestation_options_empty_json() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({});
        let resp = post_json(&app, "/attestation/options", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "username");
    }

    #[actix_web::test]
    async fn test_attestation_options_malformed_json() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_payload("malformed json {")
            .insert_header(("content-type", "application/json"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

/// Test module for POST /attestation/result endpoint
#[cfg(test)]
mod attestation_result_tests {
    use super::*;

    #[actix_web::test]
    async fn test_attestation_result_success() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        // First, get attestation options to establish a session
        let options_request = TestDataFactory::valid_attestation_options_request();
        let options_resp = post_json(&app, "/attestation/options", json!(options_request)).await;
        assert_eq!(options_resp.status(), StatusCode::OK);

        // Then, complete attestation
        let request = TestDataFactory::valid_attestation_result_request();
        let resp = post_json(&app, "/attestation/result", json!(request)).await;

        assert_eq!(resp.status(), StatusCode::OK);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_success_response(&response);
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_id() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = TestDataFactory::invalid_attestation_result_request_no_id();
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "id");
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_raw_id() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "id": TestDataFactory::valid_credential_id(),
            "response": {
                "attestationObject": TestDataFactory::valid_attestation_object(),
                "clientDataJSON": TestDataFactory::valid_client_data_json("webauthn.create")
            },
            "type": "public-key"
        });
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "rawId");
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_response() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "type": "public-key"
        });
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "response");
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_attestation_object() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "clientDataJSON": TestDataFactory::valid_client_data_json("webauthn.create")
            },
            "type": "public-key"
        });
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "attestationObject");
    }

    #[actix_web::test]
    async fn test_attestation_result_missing_client_data_json() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "attestationObject": TestDataFactory::valid_attestation_object()
            },
            "type": "public-key"
        });
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "clientDataJSON");
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_type() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let mut request = TestDataFactory::valid_attestation_result_request();
        request.type_ = "invalid-type".to_string();
        
        let resp = post_json(&app, "/attestation/result", json!(request)).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "type");
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_base64_attestation_object() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "attestationObject": TestDataFactory::malformed_base64(),
                "clientDataJSON": TestDataFactory::valid_client_data_json("webauthn.create")
            },
            "type": "public-key"
        });
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "attestationObject");
    }

    #[actix_web::test]
    async fn test_attestation_result_invalid_base64_client_data_json() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({
            "id": TestDataFactory::valid_credential_id(),
            "rawId": TestDataFactory::valid_credential_id(),
            "response": {
                "attestationObject": TestDataFactory::valid_attestation_object(),
                "clientDataJSON": TestDataFactory::malformed_base64()
            },
            "type": "public-key"
        });
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "clientDataJSON");
    }

    #[actix_web::test]
    async fn test_attestation_result_empty_json() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let request = json!({});
        let resp = post_json(&app, "/attestation/result", request).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        
        let response: crate::common::ServerResponse = response_json(resp).await.unwrap();
        assert_failed_response(&response, "id");
    }

    #[actix_web::test]
    async fn test_attestation_result_malformed_json() {
        let app = test::init_service(
            actix_web::App::new().configure(fido_server::configure_app),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_payload("malformed json {")
            .insert_header(("content-type", "application/json"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}