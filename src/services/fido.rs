//! Core FIDO service - Minimal TDD Implementation

use crate::error::{AppError, Result};
use std::collections::HashMap;
use uuid::Uuid;

/// Simple registration request
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    pub username: String,
    pub display_name: String,
}

/// Simple registration response
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    pub challenge: String,
    pub user_id: Uuid,
}

/// Simple authentication request
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    pub username: String,
}

/// Simple authentication response
#[derive(Debug, Clone)]
pub struct AuthenticationResponse {
    pub challenge: String,
    pub user_id: Uuid,
}

/// Minimal FIDO service for TDD
pub struct FidoService {
    // In-memory storage for testing
    users: HashMap<String, Uuid>,
    challenges: HashMap<String, (String, Uuid)>, // challenge -> (challenge_value, user_id)
}

impl FidoService {
    /// Create a new FIDO service
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            challenges: HashMap::new(),
        }
    }

    /// Start registration process
    pub async fn start_registration(&mut self, request: RegistrationRequest) -> Result<RegistrationResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::InvalidRequest("Username cannot be empty".to_string()));
        }

        if request.display_name.is_empty() {
            return Err(AppError::InvalidRequest("Display name cannot be empty".to_string()));
        }

        // Create or get user
        let user_id = self.users.entry(request.username.clone()).or_insert_with(Uuid::new_v4).to_owned();

        // Generate challenge
        let challenge = generate_challenge();
        let challenge_id = Uuid::new_v4().to_string();
        
        // Store challenge
        self.challenges.insert(challenge_id.clone(), (challenge.clone(), user_id));

        Ok(RegistrationResponse {
            challenge,
            user_id,
        })
    }

    /// Start authentication process
    pub async fn start_authentication(&mut self, request: AuthenticationRequest) -> Result<AuthenticationResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::InvalidRequest("Username cannot be empty".to_string()));
        }

        // Check if user exists
        let user_id = self.users.get(&request.username)
            .ok_or_else(|| AppError::AuthenticationFailed("User not found".to_string()))?;

        // Generate challenge
        let challenge = generate_challenge();
        let challenge_id = Uuid::new_v4().to_string();
        
        // Store challenge
        self.challenges.insert(challenge_id, (challenge.clone(), *user_id));

        Ok(AuthenticationResponse {
            challenge,
            user_id: *user_id,
        })
    }

    /// Get user by username (for testing)
    pub fn get_user(&self, username: &str) -> Option<Uuid> {
        self.users.get(username).copied()
    }

    /// Get challenge (for testing)
    pub fn get_challenge(&self, challenge_id: &str) -> Option<(String, Uuid)> {
        self.challenges.get(challenge_id).cloned()
    }
}

/// Generate a simple challenge
fn generate_challenge() -> String {
    use base64::{Engine as _, engine::general_purpose};
    let bytes = rand::random::<[u8; 32]>();
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registration_challenge_generation() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
        };

        let result = service.start_registration(request).await;
        
        assert!(result.is_ok(), "Registration should succeed");
        
        let response = result.unwrap();
        assert!(!response.challenge.is_empty(), "Challenge should not be empty");
        assert_ne!(response.user_id, Uuid::nil(), "User ID should be valid");
    }

    #[tokio::test]
    async fn test_registration_with_empty_username() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "".to_string(),
            display_name: "Test User".to_string(),
        };

        let result = service.start_registration(request).await;
        
        assert!(result.is_err(), "Registration with empty username should fail");
        
        match result.unwrap_err() {
            AppError::InvalidRequest(msg) => {
                assert!(msg.contains("Username cannot be empty"));
            }
            _ => panic!("Expected InvalidRequest error"),
        }
    }

    #[tokio::test]
    async fn test_registration_with_empty_display_name() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "".to_string(),
        };

        let result = service.start_registration(request).await;
        
        assert!(result.is_err(), "Registration with empty display name should fail");
        
        match result.unwrap_err() {
            AppError::InvalidRequest(msg) => {
                assert!(msg.contains("Display name cannot be empty"));
            }
            _ => panic!("Expected InvalidRequest error"),
        }
    }

    #[tokio::test]
    async fn test_authentication_challenge_generation() {
        let mut service = FidoService::new();
        
        // First register a user
        let reg_request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
        };
        let _ = service.start_registration(reg_request).await;

        // Then test authentication
        let auth_request = AuthenticationRequest {
            username: "test@example.com".to_string(),
        };

        let result = service.start_authentication(auth_request).await;
        
        assert!(result.is_ok(), "Authentication should succeed");
        
        let response = result.unwrap();
        assert!(!response.challenge.is_empty(), "Challenge should not be empty");
        assert_ne!(response.user_id, Uuid::nil(), "User ID should be valid");
    }

    #[tokio::test]
    async fn test_authentication_with_nonexistent_user() {
        let mut service = FidoService::new();
        let request = AuthenticationRequest {
            username: "nonexistent@example.com".to_string(),
        };

        let result = service.start_authentication(request).await;
        
        assert!(result.is_err(), "Authentication with nonexistent user should fail");
        
        match result.unwrap_err() {
            AppError::AuthenticationFailed(msg) => {
                assert!(msg.contains("User not found"));
            }
            _ => panic!("Expected AuthenticationFailed error"),
        }
    }

    #[tokio::test]
    async fn test_challenge_uniqueness() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
        };

        let result1 = service.start_registration(request.clone()).await.unwrap();
        let result2 = service.start_registration(request).await.unwrap();
        
        assert_ne!(result1.challenge, result2.challenge, "Challenges should be unique");
    }

    #[tokio::test]
    async fn test_user_persistence() {
        let mut service = FidoService::new();
        let request = RegistrationRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
        };

        let response1 = service.start_registration(request.clone()).await.unwrap();
        let response2 = service.start_registration(request).await.unwrap();
        
        assert_eq!(response1.user_id, response2.user_id, "User ID should be persistent");
    }
}