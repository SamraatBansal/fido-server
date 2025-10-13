//! Integration tests for individual API endpoints

use actix_web::{http::StatusCode, test};
use crate::common::{create_test_app, post_json, read_body_json};
use fido2_webauthn_server::schema::*;

#[cfg(test)]
mod attestation_endpoints_tests {
    

    #[tokio::test]
    async fn test_attestation_options_endpoint_success() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.status, "ok");
        assert_eq!(options_response.error_message, "");
        assert!(!options_response.challenge.is_empty());
        assert_eq!(options_response.rp.name, "Test RP");
        assert!(!options_response.pub_key_cred_params.is_empty());
    }

    #[tokio::test]
    async fn test_attestation_options_endpoint_invalid_method() {
        let app = create_test_app().await;

        // Test GET method (should fail)
        let req = test::TestRequest::get()
            .uri("/attestation/options")
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_attestation_options_endpoint_invalid_content_type() {
        let app = create_test_app().await;

        // Test with invalid content type
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .insert_header(("content-type", "text/plain"))
            .set_payload("invalid data")
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_attestation_options_endpoint_malformed_json() {
        let app = create_test_app().await;

        // Test with malformed JSON
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .insert_header(("content-type", "application/json"))
            .set_payload("{ invalid json }")
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_attestation_result_endpoint_success() {
        let app = create_test_app().await;

        let attestation = AttestationResponseFactory::valid();
        let response = post_json(&app, "/attestation/result", attestation).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let result_response: fido2_webauthn_server::schema::ServerResponse = 
            read_body_json(response).await;
        
        assert_eq!(result_response.status, "ok");
        assert_eq!(result_response.error_message, "");
    }

    #[tokio::test]
    async fn test_attestation_result_endpoint_invalid_method() {
        let app = create_test_app().await;

        // Test GET method (should fail)
        let req = test::TestRequest::get()
            .uri("/attestation/result")
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_attestation_result_endpoint_missing_fields() {
        let app = create_test_app().await;

        // Test with missing required fields
        let incomplete_attestation = serde_json::json!({
            "id": "test_id"
            // Missing other required fields
        });

        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&incomplete_attestation)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod assertion_endpoints_tests {
    

    #[tokio::test]
    async fn test_assertion_options_endpoint_success() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.status, "ok");
        assert_eq!(options_response.error_message, "");
        assert!(!options_response.challenge.is_empty());
        assert_eq!(options_response.rp_id, "localhost");
    }

    #[tokio::test]
    async fn test_assertion_options_endpoint_invalid_method() {
        let app = create_test_app().await;

        // Test GET method (should fail)
        let req = test::TestRequest::get()
            .uri("/assertion/options")
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_assertion_options_endpoint_empty_request() {
        let app = create_test_app().await;

        // Test with empty request body
        let empty_request = serde_json::json!({});

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&empty_request)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::OK); // Empty request should be valid (no username required)
    }

    #[tokio::test]
    async fn test_assertion_result_endpoint_success() {
        let app = create_test_app().await;

        let assertion = AssertionResponseFactory::valid();
        let response = post_json(&app, "/assertion/result", assertion).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let result_response: fido2_webauthn_server::schema::ServerResponse = 
            read_body_json(response).await;
        
        assert_eq!(result_response.status, "ok");
        assert_eq!(result_response.error_message, "");
    }

    #[tokio::test]
    async fn test_assertion_result_endpoint_invalid_method() {
        let app = create_test_app().await;

        // Test GET method (should fail)
        let req = test::TestRequest::get()
            .uri("/assertion/result")
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_assertion_result_endpoint_missing_fields() {
        let app = create_test_app().await;

        // Test with missing required fields
        let incomplete_assertion = serde_json::json!({
            "id": "test_id"
            // Missing other required fields
        });

        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&incomplete_assertion)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod endpoint_error_handling_tests {
    

    #[tokio::test]
    async fn test_endpoint_error_response_format() {
        let app = create_test_app().await;

        // Test with invalid request to trigger error
        let request = RegistrationRequestFactory::empty_username();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        
        // Check that error response has correct format
        let error_text = test::read_body(response).await;
        let error_json: serde_json::Value = serde_json::from_str(&error_text).unwrap();
        
        assert!(error_json.get("error").is_some(), "Error response should have 'error' field");
    }

    #[tokio::test]
    async fn test_endpoint_cors_headers() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .insert_header(("Origin", "http://localhost:8080"))
            .to_request();
        
        let response = test::call_service(&app, req).await;
        
        // Check for CORS headers
        assert!(response.headers().contains_key("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn test_endpoint_content_type_headers() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        // Check for content-type header
        assert!(response.headers().contains_key("content-type"));
        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().contains("application/json"));
    }

    #[tokio::test]
    async fn test_endpoint_large_payload() {
        let app = create_test_app().await;

        // Test with very large payload
        let large_request = serde_json::json!({
            "username": "a".repeat(1000),
            "displayName": "b".repeat(1000),
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&large_request)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_endpoint_unicode_handling() {
        let app = create_test_app().await;

        // Test with unicode characters
        let unicode_request = serde_json::json!({
            "username": "用户@example.com",
            "displayName": "用户名称",
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&unicode_request)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        // Should fail due to regex validation, but handle unicode properly
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod endpoint_security_tests {
    

    #[tokio::test]
    async fn test_endpoint_sql_injection_attempt() {
        let app = create_test_app().await;

        // Test with potential SQL injection
        let malicious_request = serde_json::json!({
            "username": "'; DROP TABLE users; --",
            "displayName": "Malicious User",
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&malicious_request)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        // Should fail validation, but not crash
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_endpoint_xss_attempt() {
        let app = create_test_app().await;

        // Test with potential XSS
        let xss_request = serde_json::json!({
            "username": "<script>alert('xss')</script>@example.com",
            "displayName": "<img src=x onerror=alert('xss')>",
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&xss_request)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        // Should fail validation, but not execute script
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_endpoint_null_bytes() {
        let app = create_test_app().await;

        // Test with null bytes (potential attack vector)
        let null_byte_request = serde_json::json!({
            "username": "test\0@example.com",
            "displayName": "Test\0User",
            "attestation": "direct"
        });

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&null_byte_request)
            .to_request();
        
        let response = test::call_service(&app, req).await;
        // Should handle null bytes safely
        assert!(response.status().is_client_error() || response.status().is_success());
    }
}