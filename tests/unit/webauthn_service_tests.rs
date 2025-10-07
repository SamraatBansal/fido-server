//! WebAuthn service comprehensive unit tests

use fido_server::services::webauthn::WebAuthnService;
use fido_server::services::challenge::{ChallengeService, InMemoryChallengeStore};
use fido_server::services::user::{UserService, InMemoryUserRepository};
use fido_server::services::credential::{CredentialService, InMemoryCredentialRepository};
use fido_server::schema::credential::Credential;
use fido_server::error::{AppError, Result};
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> WebAuthnService {
        let challenge_service = ChallengeService::new(InMemoryChallengeStore::new());
        let user_service = UserService::new(InMemoryUserRepository::new());
        let credential_service = CredentialService::new(InMemoryCredentialRepository::new());

        WebAuthnService::new(
            challenge_service,
            user_service,
            credential_service,
            "localhost".to_string(),
            "Test RP".to_string(),
            "https://localhost".to_string(),
        )
    }

    #[tokio::test]
    async fn test_start_registration_success() {
        let service = create_test_service();

        let result = service.start_registration(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("challengeId").is_some());
        assert!(response.get("credentialCreationOptions").is_some());

        // Verify the structure of credential creation options
        let options = response.get("credentialCreationOptions").unwrap();
        assert!(options.get("challenge").is_some());
        assert!(options.get("rp").is_some());
        assert!(options.get("user").is_some());
        assert!(options.get("pubKeyCredParams").is_some());
    }

    #[tokio::test]
    async fn test_start_registration_invalid_username() {
        let service = create_test_service();

        let result = service.start_registration(
            "invalid-email".to_string(),
            "Test User".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_start_registration_empty_display_name() {
        let service = create_test_service();

        let result = service.start_registration(
            "test@example.com".to_string(),
            "".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_start_registration_long_display_name() {
        let service = create_test_service();

        let result = service.start_registration(
            "test@example.com".to_string(),
            "a".repeat(256), // Too long
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_start_registration_existing_user() {
        let service = create_test_service();

        // Create user first
        service.user_service.create_user(
            "test@example.com".to_string(),
            "Original Name".to_string(),
        ).await.unwrap();

        // Start registration for existing user
        let result = service.start_registration(
            "test@example.com".to_string(),
            "New Name".to_string(), // This should be ignored
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("challengeId").is_some());
        
        // Verify user info in response uses original name
        let options = response.get("credentialCreationOptions").unwrap();
        let user_info = options.get("user").unwrap();
        assert_eq!(user_info.get("displayName").unwrap(), "Original Name");
    }

    #[tokio::test]
    async fn test_finish_registration_success() {
        let service = create_test_service();

        // First start registration
        let start_result = service.start_registration(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let challenge_id = start_result.get("challengeId").unwrap().as_str().unwrap();
        let credential_id = vec![1, 2, 3, 4];
        let client_data_json = br#"{"type":"webauthn.create","challenge":"test","origin":"https://localhost"}"#;
        let attestation_object = br#"{"fmt":"none","attStmt":{},"authData":"AQIDBA"}"#;

        let result = service.finish_registration(
            challenge_id.to_string(),
            credential_id,
            client_data_json.to_vec(),
            attestation_object.to_vec(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.get("status").unwrap(), "success");
        assert!(response.get("credentialId").is_some());
    }

    #[tokio::test]
    async fn test_finish_registration_invalid_challenge() {
        let service = create_test_service();

        let result = service.finish_registration(
            "non-existent-challenge".to_string(),
            vec![1, 2, 3, 4],
            vec![],
            vec![],
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_finish_registration_expired_challenge() {
        let service = create_test_service();

        // Create a challenge that expires immediately
        let user = service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let mut challenge = service.challenge_service
            .create_registration_challenge(user.id)
            .await.unwrap();
        challenge.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        
        // Manually store the expired challenge
        service.challenge_service.store.store_challenge(&challenge).await.unwrap();

        let result = service.finish_registration(
            challenge.id,
            vec![1, 2, 3, 4],
            vec![],
            vec![],
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_start_authentication_success() {
        let service = create_test_service();

        // First create a user and credential
        let user = service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user.id,
            vec![5, 6, 7, 8],
            "none".to_string(),
            vec!["internal".to_string()],
        );
        service.credential_service.register_credential(credential).await.unwrap();

        // Now start authentication
        let result = service.start_authentication(
            "test@example.com".to_string(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("challengeId").is_some());
        assert!(response.get("credentialRequestOptions").is_some());

        // Verify the structure of credential request options
        let options = response.get("credentialRequestOptions").unwrap();
        assert!(options.get("challenge").is_some());
        assert!(options.get("allowCredentials").is_some());
        
        let allow_credentials = options.get("allowCredentials").unwrap().as_array().unwrap();
        assert_eq!(allow_credentials.len(), 1);
    }

    #[tokio::test]
    async fn test_start_authentication_user_not_found() {
        let service = create_test_service();

        let result = service.start_authentication(
            "nonexistent@example.com".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_start_authentication_no_credentials() {
        let service = create_test_service();

        // Create user but no credentials
        service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let result = service.start_authentication(
            "test@example.com".to_string(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        let options = response.get("credentialRequestOptions").unwrap();
        let allow_credentials = options.get("allowCredentials").unwrap().as_array().unwrap();
        assert_eq!(allow_credentials.len(), 0);
    }

    #[tokio::test]
    async fn test_start_authentication_multiple_credentials() {
        let service = create_test_service();

        // Create user
        let user = service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        // Create multiple credentials
        let cred1 = Credential::new(
            vec![1, 2, 3, 4],
            user.id,
            vec![5, 6, 7, 8],
            "none".to_string(),
            vec!["usb".to_string()],
        );
        let cred2 = Credential::new(
            vec![5, 6, 7, 8],
            user.id,
            vec![9, 10, 11, 12],
            "packed".to_string(),
            vec!["nfc".to_string()],
        );

        service.credential_service.register_credential(cred1).await.unwrap();
        service.credential_service.register_credential(cred2).await.unwrap();

        // Start authentication
        let result = service.start_authentication(
            "test@example.com".to_string(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        let options = response.get("credentialRequestOptions").unwrap();
        let allow_credentials = options.get("allowCredentials").unwrap().as_array().unwrap();
        assert_eq!(allow_credentials.len(), 2);
    }

    #[tokio::test]
    async fn test_finish_authentication_success() {
        let service = create_test_service();

        // Create user and credential
        let user = service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user.id,
            vec![5, 6, 7, 8],
            "none".to_string(),
            vec!["internal".to_string()],
        );
        service.credential_service.register_credential(credential.clone()).await.unwrap();

        // Start authentication
        let start_result = service.start_authentication(
            "test@example.com".to_string(),
        ).await.unwrap();

        let challenge_id = start_result.get("challengeId").unwrap().as_str().unwrap();
        let client_data_json = br#"{"type":"webauthn.get","challenge":"test","origin":"https://localhost"}"#;
        let authenticator_data = br#"AQIDBA"#;
        let signature = br#"MEUCIQCdwBCYm5PjT_Q-wwOuyRvEYR_8f2vHqGhJp3b7b8jwIgYKqL8xRf9N8f2vHqGhJp3b7b8jwYKqL8xRf9N8f2vHqGhJp3b7b8jw"#;
        let user_handle = Some(user.id.as_bytes().to_vec());

        let result = service.finish_authentication(
            challenge_id.to_string(),
            credential.id.clone(),
            client_data_json.to_vec(),
            authenticator_data.to_vec(),
            signature.to_vec(),
            user_handle,
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.get("status").unwrap(), "success");
        assert!(response.get("userId").is_some());
    }

    #[tokio::test]
    async fn test_finish_authentication_invalid_challenge() {
        let service = create_test_service();

        let result = service.finish_authentication(
            "non-existent-challenge".to_string(),
            vec![1, 2, 3, 4],
            vec![],
            vec![],
            vec![],
            None,
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_finish_authentication_credential_not_found() {
        let service = create_test_service();

        // Create user and start authentication
        service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let start_result = service.start_authentication(
            "test@example.com".to_string(),
        ).await.unwrap();

        let challenge_id = start_result.get("challengeId").unwrap().as_str().unwrap();

        // Try to finish with non-existent credential
        let result = service.finish_authentication(
            challenge_id.to_string(),
            vec![9, 9, 9, 9], // Non-existent credential ID
            vec![],
            vec![],
            vec![],
            None,
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_finish_authentication_counter_regression() {
        let service = create_test_service();

        // Create user and credential
        let user = service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user.id,
            vec![5, 6, 7, 8],
            "none".to_string(),
            vec!["internal".to_string()],
        );
        service.credential_service.register_credential(credential.clone()).await.unwrap();

        // Manually set a high counter
        service.credential_service.repository
            .update_sign_count(&credential.id, 100)
            .await.unwrap();

        // Start authentication
        let start_result = service.start_authentication(
            "test@example.com".to_string(),
        ).await.unwrap();

        let challenge_id = start_result.get("challengeId").unwrap().as_str().unwrap();

        // Try to finish with lower counter (regression)
        let result = service.finish_authentication(
            challenge_id.to_string(),
            credential.id,
            vec![],
            vec![],
            vec![],
            None,
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_webauthn_service_configuration() {
        let service = create_test_service();

        // Test service configuration
        assert_eq!(service.rp_id, "localhost");
        assert_eq!(service.rp_name, "Test RP");
        assert_eq!(service.origin, "https://localhost");
    }

    #[tokio::test]
    async fn test_concurrent_registrations() {
        let service = create_test_service();

        // Start multiple concurrent registrations for the same user
        let user = "test@example.com";
        let display_name = "Test User";

        let result1 = service.start_registration(
            user.to_string(),
            display_name.to_string(),
        ).await;

        let result2 = service.start_registration(
            user.to_string(),
            display_name.to_string(),
        ).await;

        // Both should succeed (different challenges)
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let response1 = result1.unwrap();
        let response2 = result2.unwrap();

        let challenge_id1 = response1.get("challengeId").unwrap().as_str().unwrap();
        let challenge_id2 = response2.get("challengeId").unwrap().as_str().unwrap();

        // Challenges should be different
        assert_ne!(challenge_id1, challenge_id2);
    }

    #[tokio::test]
    async fn test_edge_case_empty_username() {
        let service = create_test_service();

        let result = service.start_registration(
            "".to_string(),
            "Test User".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_edge_case_very_long_username() {
        let service = create_test_service();

        let long_username = "a".repeat(300) + "@example.com";
        let result = service.start_registration(
            long_username,
            "Test User".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }
}