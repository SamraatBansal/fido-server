//! Integration tests for complete authentication flow

use actix_web::http::StatusCode;
use crate::common::{create_test_app, post_json, read_body_json};
use crate::fixtures::*;
use fido2_webauthn_server::schema::*;

#[cfg(test)]
mod authentication_flow_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_authentication_flow_success() {
        let app = create_test_app().await;

        // Step 1: Request authentication options
        let auth_request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", auth_request).await;
        
        assert_eq!(response.status(), StatusCode::OK, "Authentication options request should succeed");
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.status, "ok", "Response status should be ok");
        assert_eq!(options_response.error_message, "", "Error message should be empty");
        assert!(!options_response.challenge.is_empty(), "Challenge should not be empty");
        assert_eq!(options_response.rp_id, "localhost");
        assert_eq!(options_response.user_verification, Some("preferred".to_string()));

        // Step 2: Complete authentication with assertion
        let assertion_response = AssertionResponseFactory::valid();
        let response = post_json(&app, "/assertion/result", assertion_response).await;
        
        assert_eq!(response.status(), StatusCode::OK, "Authentication result request should succeed");
        
        let result_response: fido2_webauthn_server::schema::ServerResponse = 
            read_body_json(response).await;
        
        assert_eq!(result_response.status, "ok", "Authentication should succeed");
        assert_eq!(result_response.error_message, "", "Error message should be empty");
    }

    #[tokio::test]
    async fn test_authentication_flow_with_different_user_verification() {
        let app = create_test_app().await;

        // Test with required user verification
        let mut request = AuthenticationRequestFactory::valid();
        request.user_verification = Some("required".to_string());

        let response = post_json(&app, "/assertion/options", request).await;
        assert_eq!(response.status(), StatusCode::OK, "Request with required UV should succeed");
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.user_verification, Some("required".to_string()));

        // Test with discouraged user verification
        let mut request = AuthenticationRequestFactory::valid();
        request.user_verification = Some("discouraged".to_string());

        let response = post_json(&app, "/assertion/options", request).await;
        assert_eq!(response.status(), StatusCode::OK, "Request with discouraged UV should succeed");
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.user_verification, Some("discouraged".to_string()));
    }

    #[tokio::test]
    async fn test_authentication_flow_without_username() {
        let app = create_test_app().await;

        // Test without username (userless authentication)
        let request = AuthenticationRequestFactory::no_username();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK, "Request without username should succeed");
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.status, "ok", "Response status should be ok");
        assert!(!options_response.challenge.is_empty(), "Challenge should not be empty");
    }

    #[tokio::test]
    async fn test_authentication_flow_invalid_request_data() {
        let app = create_test_app().await;

        // Test with invalid user verification
        let request = AuthenticationRequestFactory::invalid_user_verification();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid user verification should be rejected");
    }

    #[tokio::test]
    async fn test_authentication_flow_invalid_assertion_response() {
        let app = create_test_app().await;

        // First get valid options
        let auth_request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", auth_request).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Then try to complete with invalid assertion
        let assertion_response = AssertionResponseFactory::empty_id();
        let response = post_json(&app, "/assertion/result", assertion_response).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Empty credential ID should be rejected");

        let assertion_response = AssertionResponseFactory::invalid_authenticator_data();
        let response = post_json(&app, "/assertion/result", assertion_response).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid authenticator data should be rejected");

        let assertion_response = AssertionResponseFactory::empty_signature();
        let response = post_json(&app, "/assertion/result", assertion_response).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Empty signature should be rejected");
    }

    #[tokio::test]
    async fn test_authentication_flow_challenge_uniqueness() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        
        // Generate multiple challenges for the same user
        let response1 = post_json(&app, "/assertion/options", request.clone()).await;
        let response2 = post_json(&app, "/assertion/options", request.clone()).await;
        let response3 = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::OK);
        
        let options1: crate::fixtures::ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response1).await;
        let options2: crate::fixtures::ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response2).await;
        let options3: crate::fixtures::ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response3).await;
        
        // All challenges should be different
        assert_ne!(options1.challenge, options2.challenge, "Challenges should be unique");
        assert_ne!(options2.challenge, options3.challenge, "Challenges should be unique");
        assert_ne!(options1.challenge, options3.challenge, "Challenges should be unique");
    }

    #[tokio::test]
    async fn test_authentication_flow_rp_id_consistency() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        // Verify RP ID consistency
        assert_eq!(options_response.rp_id, "localhost");
    }

    #[tokio::test]
    async fn test_authentication_flow_allow_credentials() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        // For mock implementation, allowCredentials should be None
        assert!(options_response.allow_credentials.is_none(), 
                "Allow credentials should be None in mock implementation");
    }

    #[tokio::test]
    async fn test_authentication_flow_timeout_configuration() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        // Verify timeout configuration
        assert_eq!(options_response.timeout, Some(60000), "Timeout should be 60000ms");
    }

    #[tokio::test]
    async fn test_authentication_flow_extensions() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        // Extensions should be None for basic authentication
        assert!(options_response.extensions.is_none(), "Extensions should be None for basic authentication");
    }

    #[tokio::test]
    async fn test_authentication_flow_different_usernames() {
        let app = create_test_app().await;

        // Test with different usernames
        let usernames = [
            "user1@example.com",
            "user2@example.com", 
            "test.user@domain.com",
            "user+tag@example.org"
        ];

        for username in usernames {
            let mut request = AuthenticationRequestFactory::valid();
            request.username = Some(username.to_string());

            let response = post_json(&app, "/assertion/options", request).await;
            assert_eq!(response.status(), StatusCode::OK, "Request for user '{}' should succeed", username);
            
            let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
                read_body_json(response).await;
            
            assert_eq!(options_response.status, "ok", "Response status should be ok");
            assert!(!options_response.challenge.is_empty(), "Challenge should not be empty");
        }
    }

    #[tokio::test]
    async fn test_authentication_flow_challenge_format() {
        let app = create_test_app().await;

        let request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialGetOptionsResponse = 
            read_body_json(response).await;
        
        let challenge = &options_response.challenge;
        
        // Challenge should be valid base64url
        assert!(fido2_webauthn_server::utils::crypto::decode_base64url(challenge).is_ok(),
                "Challenge should be valid base64url");

        // Challenge should be reasonable length (16+ bytes when decoded)
        let decoded = fido2_webauthn_server::utils::crypto::decode_base64url(challenge).unwrap();
        assert!(decoded.len() >= 16, "Challenge should be at least 16 bytes when decoded");
    }

    #[tokio::test]
    async fn test_authentication_flow_with_user_handle() {
        let app = create_test_app().await;

        // First get authentication options
        let auth_request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", auth_request).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Complete authentication with assertion that includes user handle
        let mut assertion_response = AssertionResponseFactory::valid();
        assertion_response.response.user_handle = Some(generate_test_user_id());
        
        let response = post_json(&app, "/assertion/result", assertion_response).await;
        assert_eq!(response.status(), StatusCode::OK, "Authentication with user handle should succeed");
        
        let result_response: fido2_webauthn_server::schema::ServerResponse = 
            read_body_json(response).await;
        
        assert_eq!(result_response.status, "ok", "Authentication should succeed");
    }

    #[tokio::test]
    async fn test_authentication_flow_without_user_handle() {
        let app = create_test_app().await;

        // First get authentication options
        let auth_request = AuthenticationRequestFactory::valid();
        let response = post_json(&app, "/assertion/options", auth_request).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Complete authentication with assertion that doesn't include user handle
        let mut assertion_response = AssertionResponseFactory::valid();
        assertion_response.response.user_handle = None;
        
        let response = post_json(&app, "/assertion/result", assertion_response).await;
        assert_eq!(response.status(), StatusCode::OK, "Authentication without user handle should succeed");
        
        let result_response: fido2_webauthn_server::schema::ServerResponse = 
            read_body_json(response).await;
        
        assert_eq!(result_response.status, "ok", "Authentication should succeed");
    }
}