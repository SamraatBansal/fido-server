//! User schema definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// Unique user identifier
    pub id: Uuid,
    /// User's email address (used as username)
    pub username: String,
    /// Display name for the user
    pub display_name: String,
    /// When the user was created
    pub created_at: DateTime<Utc>,
    /// When the user was last updated
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user
    pub fn new(username: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            display_name,
            created_at: now,
            updated_at: now,
        }
    }

    /// Validate user data
    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }

        if !self.username.contains('@') {
            return Err("Username must be a valid email address".to_string());
        }

        if self.display_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }

        if self.display_name.len() > 255 {
            return Err("Display name too long (max 255 characters)".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "test@example.com".to_string(),
            "Test User".to_string(),
        );

        assert!(!user.id.to_string().is_empty());
        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
    }

    #[test]
    fn test_user_validation_success() {
        let user = User::new(
            "test@example.com".to_string(),
            "Test User".to_string(),
        );

        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_user_validation_empty_username() {
        let user = User::new(
            "".to_string(),
            "Test User".to_string(),
        );

        assert!(user.validate().is_err());
    }

    #[test]
    fn test_user_validation_invalid_email() {
        let user = User::new(
            "invalid-email".to_string(),
            "Test User".to_string(),
        );

        assert!(user.validate().is_err());
    }

    #[test]
    fn test_user_validation_empty_display_name() {
        let user = User::new(
            "test@example.com".to_string(),
            "".to_string(),
        );

        assert!(user.validate().is_err());
    }

    #[test]
    fn test_user_validation_too_long_display_name() {
        let user = User::new(
            "test@example.com".to_string(),
            "a".repeat(256),
        );

        assert!(user.validate().is_err());
    }
}