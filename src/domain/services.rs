//! Domain services for business logic

use crate::domain::entities::{User, Credential, Challenge, ChallengeType};
use crate::domain::value_objects::{UserId, Username, CredentialId, ChallengeValue};
use crate::error::{AppError, Result};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

/// User domain service
pub struct UserService;

impl UserService {
    pub fn create_user(username: String, display_name: String) -> Result<User> {
        let _validated_username = Username::new(username.clone())?;
        
        if display_name.is_empty() {
            return Err(AppError::ValidationError(
                "Display name cannot be empty".to_string(),
            ));
        }

        Ok(User::new(username, display_name))
    }

    pub fn validate_user_for_registration(user: &User) -> Result<()> {
        if !user.is_active {
            return Err(AppError::ValidationError(
                "User account is not active".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_user_for_authentication(user: &User) -> Result<()> {
        if !user.is_active {
            return Err(AppError::ValidationError(
                "User account is not active".to_string(),
            ));
        }

        Ok(())
    }
}

/// Credential domain service
pub struct CredentialService;

impl CredentialService {
    pub fn create_credential(
        user_id: Uuid,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        attestation_type: String,
    ) -> Result<Credential> {
        if credential_id.is_empty() {
            return Err(AppError::ValidationError(
                "Credential ID cannot be empty".to_string(),
            ));
        }

        if public_key.is_empty() {
            return Err(AppError::ValidationError(
                "Public key cannot be empty".to_string(),
            ));
        }

        Ok(Credential::new(
            user_id,
            credential_id,
            public_key,
            attestation_type,
        ))
    }

    pub fn validate_credential_for_authentication(credential: &Credential) -> Result<()> {
        // Add any business rules for credential validation
        Ok(())
    }

    pub fn update_sign_count(credential: &mut Credential, new_count: u32) -> Result<()> {
        if new_count <= credential.sign_count {
            return Err(AppError::ValidationError(
                "Sign count must be monotonically increasing".to_string(),
            ));
        }

        credential.sign_count = new_count;
        credential.last_used_at = Some(Utc::now());
        Ok(())
    }
}

/// Challenge domain service
pub struct ChallengeService;

impl ChallengeService {
    pub fn create_registration_challenge(user_id: Option<Uuid>) -> Challenge {
        let challenge_bytes = ChallengeValue::generate().0;
        let expires_at = Utc::now() + Duration::minutes(5); // 5 minute expiry
        
        Challenge::new(
            challenge_bytes,
            user_id,
            ChallengeType::Registration,
            expires_at,
        )
    }

    pub fn create_authentication_challenge(user_id: Uuid) -> Challenge {
        let challenge_bytes = ChallengeValue::generate().0;
        let expires_at = Utc::now() + Duration::minutes(5); // 5 minute expiry
        
        Challenge::new(
            challenge_bytes,
            Some(user_id),
            ChallengeType::Authentication,
            expires_at,
        )
    }

    pub fn validate_challenge(challenge: &Challenge) -> Result<()> {
        if challenge.is_expired() {
            return Err(AppError::ValidationError(
                "Challenge has expired".to_string(),
            ));
        }

        if challenge.is_used() {
            return Err(AppError::ValidationError(
                "Challenge has already been used".to_string(),
            ));
        }

        Ok(())
    }

    pub fn mark_challenge_used(challenge: &mut Challenge) -> Result<()> {
        if challenge.is_used() {
            return Err(AppError::ValidationError(
                "Challenge has already been used".to_string(),
            ));
        }

        challenge.used_at = Some(Utc::now());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_service_create_user_success() {
        let result = UserService::create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        );
        assert!(result.is_ok());
        
        let user = result.unwrap();
        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(user.is_active);
    }

    #[test]
    fn test_user_service_create_user_invalid_username() {
        let result = UserService::create_user(
            "invalid-username".to_string(),
            "Test User".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_user_service_create_user_empty_display_name() {
        let result = UserService::create_user(
            "test@example.com".to_string(),
            "".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_service_create_credential_success() {
        let user_id = Uuid::new_v4();
        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];
        
        let result = CredentialService::create_credential(
            user_id,
            credential_id.clone(),
            public_key.clone(),
            "packed".to_string(),
        );
        
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.credential_public_key, public_key);
    }

    #[test]
    fn test_challenge_service_create_registration_challenge() {
        let challenge = ChallengeService::create_registration_challenge(None);
        assert_eq!(challenge.challenge.len(), 32);
        assert!(matches!(challenge.challenge_type, ChallengeType::Registration));
        assert!(!challenge.is_expired());
        assert!(!challenge.is_used());
    }

    #[test]
    fn test_challenge_service_validate_challenge_success() {
        let challenge = ChallengeService::create_registration_challenge(None);
        let result = ChallengeService::validate_challenge(&challenge);
        assert!(result.is_ok());
    }

    #[test]
    fn test_challenge_service_mark_challenge_used() {
        let mut challenge = ChallengeService::create_registration_challenge(None);
        assert!(!challenge.is_used());
        
        let result = ChallengeService::mark_challenge_used(&mut challenge);
        assert!(result.is_ok());
        assert!(challenge.is_used());
    }
}