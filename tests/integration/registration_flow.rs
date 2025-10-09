//! Integration tests for complete registration flow

use actix_web::http::StatusCode;
use crate::common::{create_test_app, post_json, read_body_json};
use fido2_webauthn_server::schema::*;

#[cfg(test)]
mod registration_flow_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_registration_flow_success() {
        let app = create_test_app().await;

        // Step 1: Request registration options
        let registration_request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", registration_request).await;
        
        assert_eq!(response.status(), StatusCode::OK, "Registration options request should succeed");
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.status, "ok", "Response status should be ok");
        assert_eq!(options_response.error_message, "", "Error message should be empty");
        assert!(!options_response.challenge.is_empty(), "Challenge should not be empty");
        assert_eq!(options_response.rp.name, "Test RP");
        assert_eq!(options_response.user.name, "testuser@example.com");
        assert_eq!(options_response.user.display_name, "Test User");
        assert!(!options_response.pub_key_cred_params.is_empty(), "Should have credential parameters");

        // Step 2: Complete registration with attestation
        let attestation_response = AttestationResponseFactory::valid();
        let response = post_json(&app, "/attestation/result", attestation_response).await;
        
        assert_eq!(response.status(), StatusCode::OK, "Registration result request should succeed");
        
        let result_response: fido2_webauthn_server::schema::ServerResponse = 
            read_body_json(response).await;
        
        assert_eq!(result_response.status, "ok", "Registration should succeed");
        assert_eq!(result_response.error_message, "", "Error message should be empty");
    }

    #[tokio::test]
    async fn test_registration_flow_with_different_authenticator_selection() {
        let app = create_test_app().await;

        // Test with platform authenticator
        let mut request = RegistrationRequestFactory::valid();
        request.authenticator_selection = Some(fido2_webauthn_server::schema::AuthenticatorSelectionCriteria {
            require_resident_key: Some(true),
            user_verification: Some("required".to_string()),
            authenticator_attachment: Some("platform".to_string()),
        });

        let response = post_json(&app, "/attestation/options", request).await;
        assert_eq!(response.status(), StatusCode::OK, "Request with platform authenticator should succeed");
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.authenticator_selection.as_ref().unwrap().authenticator_attachment, 
                  Some("platform".to_string()));
        assert_eq!(options_response.authenticator_selection.as_ref().unwrap().require_resident_key, 
                  Some(true));
        assert_eq!(options_response.authenticator_selection.as_ref().unwrap().user_verification, 
                  Some("required".to_string()));
    }

    #[tokio::test]
    async fn test_registration_flow_with_different_attestation_conveyance() {
        let app = create_test_app().await;

        // Test with none attestation
        let mut request = RegistrationRequestFactory::valid();
        request.attestation = Some("none".to_string());

        let response = post_json(&app, "/attestation/options", request).await;
        assert_eq!(response.status(), StatusCode::OK, "Request with none attestation should succeed");
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.attestation, Some("none".to_string()));

        // Test with indirect attestation
        let mut request = RegistrationRequestFactory::valid();
        request.attestation = Some("indirect".to_string());

        let response = post_json(&app, "/attestation/options", request).await;
        assert_eq!(response.status(), StatusCode::OK, "Request with indirect attestation should succeed");
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        assert_eq!(options_response.attestation, Some("indirect".to_string()));
    }

    #[tokio::test]
    async fn test_registration_flow_invalid_request_data() {
        let app = create_test_app().await;

        // Test with empty username
        let request = RegistrationRequestFactory::empty_username();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Empty username should be rejected");

        // Test with invalid attestation
        let request = RegistrationRequestFactory::invalid_attestation();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid attestation should be rejected");

        // Test with long username
        let request = RegistrationRequestFactory::long_username();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Long username should be rejected");
    }

    #[tokio::test]
    async fn test_registration_flow_invalid_attestation_response() {
        let app = create_test_app().await;

        // First get valid options
        let registration_request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", registration_request).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Then try to complete with invalid attestation
        let attestation_response = AttestationResponseFactory::empty_id();
        let response = post_json(&app, "/attestation/result", attestation_response).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Empty credential ID should be rejected");

        let attestation_response = AttestationResponseFactory::invalid_type();
        let response = post_json(&app, "/attestation/result", attestation_response).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid credential type should be rejected");

        let attestation_response = AttestationResponseFactory::invalid_client_data();
        let response = post_json(&app, "/attestation/result", attestation_response).await;
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid client data should be rejected");
    }

    #[tokio::test]
    async fn test_registration_flow_challenge_uniqueness() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        
        // Generate multiple challenges for the same user
        let response1 = post_json(&app, "/attestation/options", request.clone()).await;
        let response2 = post_json(&app, "/attestation/options", request.clone()).await;
        let response3 = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::OK);
        
        let options1: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response1).await;
        let options2: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response2).await;
        let options3: crate::fixtures::ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response3).await;
        
        // All challenges should be different
        assert_ne!(options1.challenge, options2.challenge, "Challenges should be unique");
        assert_ne!(options2.challenge, options3.challenge, "Challenges should be unique");
        assert_ne!(options1.challenge, options3.challenge, "Challenges should be unique");
    }

    #[tokio::test]
    async fn test_registration_flow_user_data_consistency() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        // Verify user data consistency
        assert_eq!(options_response.user.name, "testuser@example.com");
        assert_eq!(options_response.user.display_name, "Test User");
        assert!(!options_response.user.id.is_empty(), "User ID should not be empty");
        
        // User ID should be valid base64url
        assert!(fido2_webauthn_server::utils::crypto::decode_base64url(&options_response.user.id).is_ok(),
                "User ID should be valid base64url");
    }

    #[tokio::test]
    async fn test_registration_flow_rp_data_consistency() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        // Verify RP data consistency
        assert_eq!(options_response.rp.name, "Test RP");
        assert_eq!(options_response.rp.id, Some("localhost".to_string()));
    }

    #[tokio::test]
    async fn test_registration_flow_credential_parameters() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        // Verify credential parameters
        assert!(!options_response.pub_key_cred_params.is_empty(), "Should have credential parameters");
        
        // Should include ES256 (-7)
        let has_es256 = options_response.pub_key_cred_params.iter()
            .any(|p| p.alg == -7 && p.cred_type == "public-key");
        assert!(has_es256, "Should include ES256 algorithm");
        
        // All parameters should have type "public-key"
        for param in &options_response.pub_key_cred_params {
            assert_eq!(param.cred_type, "public-key", "All credential types should be 'public-key'");
        }
    }

    #[tokio::test]
    async fn test_registration_flow_timeout_configuration() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        // Verify timeout configuration
        assert_eq!(options_response.timeout, Some(60000), "Timeout should be 60000ms");
    }

    #[tokio::test]
    async fn test_registration_flow_exclude_credentials() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        // For new registration, excludeCredentials should be empty or None
        match options_response.exclude_credentials {
            Some(creds) => assert!(creds.is_empty(), "Exclude credentials should be empty for new registration"),
            None => {}, // None is also acceptable
        }
    }

    #[tokio::test]
    async fn test_registration_flow_extensions() {
        let app = create_test_app().await;

        let request = RegistrationRequestFactory::valid();
        let response = post_json(&app, "/attestation/options", request).await;
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let options_response: ServerPublicKeyCredentialCreationOptionsResponse = 
            read_body_json(response).await;
        
        // Extensions should be None for basic registration
        assert!(options_response.extensions.is_none(), "Extensions should be None for basic registration");
    }
}